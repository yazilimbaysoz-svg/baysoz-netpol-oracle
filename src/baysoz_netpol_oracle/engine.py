"""Deterministic NetworkPolicy reachability evaluator.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

from .model import (
    LabelSelector,
    ManifestError,
    Peer,
    PolicyRule,
    SUPPORTED_PROTOCOLS,
    Topology,
    Workload,
)

METADATA_IP = "169.254.169.254"


@dataclass(frozen=True, slots=True)
class Endpoint:
    namespace: str | None = None
    pod: str | None = None
    address: str | None = None

    @classmethod
    def workload(cls, namespace: str, name: str) -> Endpoint:
        return cls(namespace=namespace, pod=name)

    @classmethod
    def ip(cls, value: str) -> Endpoint:
        try:
            return cls(address=str(ip_address(value)))
        except ValueError as exc:
            raise ManifestError(f"invalid IP address {value!r}: {exc}") from exc

    @classmethod
    def parse(cls, value: str) -> Endpoint:
        if "/" in value:
            namespace, _, name = value.partition("/")
            if not namespace or not name:
                raise ManifestError(f"invalid workload endpoint {value!r}; use namespace/pod")
            return cls.workload(namespace, name)
        return cls.ip(value)

    @property
    def is_ip(self) -> bool:
        return self.address is not None

    @property
    def key(self) -> str:
        if self.address is not None:
            return self.address
        return f"{self.namespace}/{self.pod}"

    def __post_init__(self) -> None:
        workload_fields = (self.namespace, self.pod)
        if self.address is not None and any(item is not None for item in workload_fields):
            raise ManifestError("endpoint cannot be both an IP address and a workload")
        if self.address is None and any(item is None or item == "" for item in workload_fields):
            raise ManifestError("workload endpoint requires a namespace and a pod name")


@dataclass(frozen=True, slots=True)
class DirectionTrace:
    isolated: bool
    allowed: bool
    evidence: tuple[str, ...]
    policies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Decision:
    source: str
    destination: str
    port: int
    protocol: str
    ingress: DirectionTrace
    egress: DirectionTrace

    @property
    def allowed(self) -> bool:
        return self.ingress.allowed and self.egress.allowed

    @property
    def verdict(self) -> str:
        return "ALLOWED" if self.allowed else "DENIED"

    @property
    def summary(self) -> str:
        if self.allowed:
            return "ALLOWED: ingress and egress authorization checks both permit this flow"
        denied = [name for name, trace in (("ingress", self.ingress), ("egress", self.egress)) if not trace.allowed]
        return f"DENIED: {' and '.join(denied)} authorization check(s) have no matching allow rule"


def _describe_selector(selector: LabelSelector) -> str:
    return selector.describe()


def _peer_matches(
    peer: Peer | None,
    endpoint: Endpoint,
    policy_namespace: str,
    topology: Topology,
    direction: str,
) -> str | None:
    side = "source" if direction == "Ingress" else "destination"
    if peer is None or peer.is_any:
        return f"any {side}"
    if peer.ip_block is not None:
        if endpoint.address is None:
            return None
        address = ip_address(endpoint.address)
        if peer.ip_block.contains(address):
            return f"{side} address {address} matches {peer.ip_block.describe()}"
        return None
    if endpoint.address is not None:
        return None
    workload = topology.workloads.get((endpoint.namespace, endpoint.pod))
    if workload is None:
        raise ManifestError(f"unknown workload endpoint {endpoint.key}")
    if peer.namespace_selector is None:
        if workload.namespace != policy_namespace:
            return None
        if peer.pod_selector is not None and not peer.pod_selector.matches(workload.labels):
            return None
        return f"{side} pod {workload.id} matches podSelector {_describe_selector(peer.pod_selector)}"
    namespace = topology.namespaces.get(workload.namespace)
    if namespace is None or not peer.namespace_selector.matches(namespace.labels):
        return None
    if peer.pod_selector is None:
        selector = _describe_selector(peer.namespace_selector)
        return f"{side} namespace {namespace.name} matches namespaceSelector {selector}"
    if not peer.pod_selector.matches(workload.labels):
        return None
    return (
        f"{side} namespace {namespace.name} matches namespaceSelector "
        f"{_describe_selector(peer.namespace_selector)} and pod {workload.id} matches podSelector "
        f"{_describe_selector(peer.pod_selector)}"
    )


def _rule_port_text(rule: PolicyRule) -> str:
    if rule.ports is None:
        return "all ports/protocols"
    return " or ".join(port.describe() for port in rule.ports)


def _direction_trace(
    topology: Topology,
    workload: Workload,
    direction: str,
    peer_endpoint: Endpoint,
    port: int,
    protocol: str,
    target: Workload | None,
) -> DirectionTrace:
    policies = sorted(
        (
            policy
            for policy in topology.policies.values()
            if policy.namespace == workload.namespace
            and (policy.ingress_isolation if direction == "Ingress" else policy.egress_isolation)
            and policy.applies_to(workload)
        ),
        key=lambda policy: policy.id,
    )
    if not policies:
        return DirectionTrace(
            isolated=False,
            allowed=True,
            evidence=(f"no {direction.lower()} NetworkPolicy selects {workload.id}; traffic is unrestricted",),
            policies=(),
        )
    evidence: list[str] = []
    skipped: list[str] = []
    for policy in policies:
        for rule_index, rule in enumerate(policy.rules_for(direction)):
            if rule.ports is not None and not any(
                port_rule.matches(port, protocol, target) for port_rule in rule.ports
            ):
                skipped.append(f"{policy.id} {direction.lower()} rule {rule_index} requires {_rule_port_text(rule)}")
                continue
            peers: tuple[Peer | None, ...] = rule.peers if rule.peers is not None else (None,)
            for peer_index, peer in enumerate(peers):
                reason = _peer_matches(peer, peer_endpoint, policy.namespace, topology, direction)
                if reason is not None:
                    evidence.append(
                        f"ALLOW {policy.id} {direction.lower()} rule {rule_index} peer {peer_index}: {reason}; "
                        f"port {protocol}/{port} matches {_rule_port_text(rule)}"
                    )
                    return DirectionTrace(True, True, tuple(evidence), tuple(policy.id for policy in policies))
    detail = f"no {direction.lower()} rule matched; {len(policies)} policy(ies) isolate {workload.id}"
    evidence.append(detail)
    evidence.extend(skipped[:3])
    return DirectionTrace(True, False, tuple(evidence), tuple(policy.id for policy in policies))


def _unconstrained(description: str) -> DirectionTrace:
    return DirectionTrace(isolated=False, allowed=True, evidence=(description,), policies=())


def query(
    topology: Topology,
    source: Endpoint,
    destination: Endpoint,
    port: int,
    protocol: str = "TCP",
) -> Decision:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManifestError(f"port {port!r} outside 1..65535")
    normalized_protocol = protocol.upper()
    if normalized_protocol not in SUPPORTED_PROTOCOLS:
        raise ManifestError(f"unsupported protocol {protocol!r}; expected TCP, UDP or SCTP")
    if not source.is_ip:
        if (source.namespace, source.pod) not in topology.workloads:
            raise ManifestError(f"unknown source workload {source.key}")
    if not destination.is_ip:
        if (destination.namespace, destination.pod) not in topology.workloads:
            raise ManifestError(f"unknown destination workload {destination.key}")
    target = None if destination.is_ip else topology.workloads[(destination.namespace, destination.pod)]
    if destination.is_ip:
        ingress = _unconstrained("destination is an IP address; no ingress policy applies")
    else:
        ingress = _direction_trace(topology, target, "Ingress", source, port, normalized_protocol, target)
    if source.is_ip:
        egress = _unconstrained("source is an IP address; no egress policy applies")
    else:
        origin = topology.workloads[(source.namespace, source.pod)]
        egress = _direction_trace(topology, origin, "Egress", destination, port, normalized_protocol, target)
    return Decision(source.key, destination.key, port, normalized_protocol, ingress, egress)


__all__ = ["Decision", "DirectionTrace", "Endpoint", "METADATA_IP", "query"]
