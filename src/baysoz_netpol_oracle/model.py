"""Immutable domain model for Kubernetes NetworkPolicy reachability analysis.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Any, Mapping

IPNetwork = IPv4Network | IPv6Network
IPAddress = IPv4Address | IPv6Address

SUPPORTED_OPERATORS = frozenset({"In", "NotIn", "Exists", "DoesNotExist"})
SUPPORTED_PROTOCOLS = frozenset({"TCP", "UDP", "SCTP"})
SUPPORTED_POLICY_TYPES = frozenset({"Ingress", "Egress"})


class ManifestError(ValueError):
    """Raised when manifests are malformed or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class MatchExpression:
    key: str
    operator: str
    values: tuple[str, ...] = ()

    def matches(self, labels: Mapping[str, str]) -> bool:
        present = self.key in labels
        actual = labels.get(self.key)
        if self.operator == "In":
            return present and actual in self.values
        if self.operator == "NotIn":
            return not present or actual not in self.values
        if self.operator == "Exists":
            return present
        if self.operator == "DoesNotExist":
            return not present
        raise ManifestError(f"unsupported matchExpression operator {self.operator!r}")

    def describe(self) -> str:
        if self.values:
            joined = ",".join(sorted(self.values))
            return f"{self.key} {self.operator} {{{joined}}}"
        return f"{self.key} {self.operator}"


@dataclass(frozen=True, slots=True)
class LabelSelector:
    match_labels: tuple[tuple[str, str], ...] = ()
    match_expressions: tuple[MatchExpression, ...] = ()

    @classmethod
    def from_value(cls, value: Any, where: str) -> LabelSelector:
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise ManifestError(f"{where}: label selector must be a mapping")
        unknown = sorted(set(value) - {"matchLabels", "matchExpressions"})
        if unknown:
            raise ManifestError(f"{where}: unsupported selector keys {unknown}")
        raw_labels = value.get("matchLabels") or {}
        if not isinstance(raw_labels, dict):
            raise ManifestError(f"{where}: matchLabels must be a mapping")
        labels: list[tuple[str, str]] = []
        for key, item in raw_labels.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise ManifestError(f"{where}: matchLabels keys and values must be strings")
            labels.append((key, item))
        raw_expressions = value.get("matchExpressions") or []
        if not isinstance(raw_expressions, list):
            raise ManifestError(f"{where}: matchExpressions must be a list")
        expressions: list[MatchExpression] = []
        for index, raw in enumerate(raw_expressions):
            location = f"{where} matchExpressions[{index}]"
            if not isinstance(raw, dict):
                raise ManifestError(f"{location}: must be a mapping")
            unknown_expression = sorted(set(raw) - {"key", "operator", "values"})
            if unknown_expression:
                raise ManifestError(f"{location}: unsupported keys {unknown_expression}")
            key = raw.get("key")
            operator = raw.get("operator")
            values = raw.get("values") or ()
            if not isinstance(key, str) or not key:
                raise ManifestError(f"{location}: key must be a non-empty string")
            if operator not in SUPPORTED_OPERATORS:
                raise ManifestError(f"{location}: unsupported operator {operator!r}")
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ManifestError(f"{location}: values must be a list of strings")
            if operator in {"In", "NotIn"} and not values:
                raise ManifestError(f"{location}: {operator} requires at least one value")
            if operator in {"Exists", "DoesNotExist"} and values:
                raise ManifestError(f"{location}: {operator} must not declare values")
            expressions.append(MatchExpression(key, operator, tuple(values)))
        return cls(tuple(sorted(labels)), tuple(expressions))

    def matches(self, labels: Mapping[str, str]) -> bool:
        if any(labels.get(key) != value for key, value in self.match_labels):
            return False
        return all(expression.matches(labels) for expression in self.match_expressions)

    def describe(self) -> str:
        parts = [f"{key}={value}" for key, value in self.match_labels]
        parts.extend(expression.describe() for expression in self.match_expressions)
        return "[" + ", ".join(parts) + "]" if parts else "[all]"


@dataclass(frozen=True, slots=True)
class IPBlock:
    cidr: IPNetwork
    excepts: tuple[IPNetwork, ...] = ()

    @classmethod
    def from_value(cls, value: Any, where: str) -> IPBlock:
        if not isinstance(value, dict):
            raise ManifestError(f"{where}: ipBlock must be a mapping")
        unknown = sorted(set(value) - {"cidr", "except"})
        if unknown:
            raise ManifestError(f"{where}: unsupported ipBlock keys {unknown}")
        raw_cidr = value.get("cidr")
        if not isinstance(raw_cidr, str):
            raise ManifestError(f"{where}: ipBlock.cidr must be a string")
        try:
            cidr = ip_network(raw_cidr, strict=True)
        except ValueError as exc:
            raise ManifestError(f"{where}: invalid ipBlock.cidr {raw_cidr!r}: {exc}") from exc
        raw_excepts = value.get("except") or []
        if not isinstance(raw_excepts, list):
            raise ManifestError(f"{where}: ipBlock.except must be a list")
        excepts: list[IPNetwork] = []
        for index, raw in enumerate(raw_excepts):
            try:
                excluded = ip_network(raw, strict=True)
            except ValueError as exc:
                raise ManifestError(f"{where} except[{index}]: invalid CIDR {raw!r}: {exc}") from exc
            if excluded.version != cidr.version or not excluded.subnet_of(cidr):
                raise ManifestError(f"{where} except[{index}]: {raw!r} is not inside {raw_cidr}")
            excepts.append(excluded)
        return cls(cidr, tuple(excepts))

    def contains(self, address: IPAddress) -> bool:
        if address.version != self.cidr.version or address not in self.cidr:
            return False
        return not any(address in excluded for excluded in self.excepts)

    def describe(self) -> str:
        excluded = ",".join(str(item) for item in self.excepts)
        return f"ipBlock {self.cidr}" + (f" except {excluded}" if excluded else "")


@dataclass(frozen=True, slots=True)
class Peer:
    pod_selector: LabelSelector | None = None
    namespace_selector: LabelSelector | None = None
    ip_block: IPBlock | None = None

    @classmethod
    def from_value(cls, value: Any, where: str) -> Peer:
        if not isinstance(value, dict):
            raise ManifestError(f"{where}: peer must be a mapping")
        unknown = sorted(set(value) - {"podSelector", "namespaceSelector", "ipBlock"})
        if unknown:
            raise ManifestError(f"{where}: unsupported peer keys {unknown}")
        if "ipBlock" in value and ("podSelector" in value or "namespaceSelector" in value):
            raise ManifestError(f"{where}: ipBlock cannot be combined with selector fields")
        pod_selector = (
            LabelSelector.from_value(value["podSelector"], f"{where}.podSelector")
            if "podSelector" in value
            else None
        )
        namespace_selector = (
            LabelSelector.from_value(value["namespaceSelector"], f"{where}.namespaceSelector")
            if "namespaceSelector" in value
            else None
        )
        ip_block = IPBlock.from_value(value["ipBlock"], f"{where}.ipBlock") if "ipBlock" in value else None
        return cls(pod_selector, namespace_selector, ip_block)

    @property
    def is_any(self) -> bool:
        return self.pod_selector is None and self.namespace_selector is None and self.ip_block is None


@dataclass(frozen=True, slots=True)
class PortRule:
    protocol: str
    port: int | str | None = None

    @classmethod
    def from_value(cls, value: Any, where: str) -> PortRule:
        if not isinstance(value, dict):
            raise ManifestError(f"{where}: port must be a mapping")
        unknown = sorted(set(value) - {"protocol", "port"})
        if unknown:
            raise ManifestError(f"{where}: unsupported port keys {unknown}")
        protocol = str(value.get("protocol", "TCP")).upper()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ManifestError(f"{where}: unsupported protocol {protocol!r}")
        raw_port = value.get("port")
        if raw_port is None:
            return cls(protocol, None)
        if isinstance(raw_port, bool):
            raise ManifestError(f"{where}: port must be an integer or a named port string")
        if isinstance(raw_port, int):
            if not 1 <= raw_port <= 65535:
                raise ManifestError(f"{where}: port {raw_port} outside 1..65535")
            return cls(protocol, raw_port)
        if isinstance(raw_port, str) and raw_port:
            return cls(protocol, raw_port)
        raise ManifestError(f"{where}: port must be an integer or a non-empty named port string")

    def matches(self, port: int, protocol: str, target: Workload | None) -> bool:
        if protocol.upper() != self.protocol:
            return False
        if self.port is None:
            return True
        if isinstance(self.port, int):
            return self.port == port
        if target is None:
            return False
        return target.named_port(self.port, protocol) == port

    def describe(self) -> str:
        if self.port is None:
            return f"{self.protocol}/all"
        return f"{self.protocol}/{self.port}"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    peers: tuple[Peer, ...] | None = None
    ports: tuple[PortRule, ...] | None = None

    @classmethod
    def from_value(cls, value: Any, where: str, peer_key: str) -> PolicyRule:
        if not isinstance(value, dict):
            raise ManifestError(f"{where}: rule must be a mapping")
        unknown = sorted(set(value) - {peer_key, "ports"})
        if unknown:
            raise ManifestError(f"{where}: unsupported rule keys {unknown}")
        raw_peers = value.get(peer_key)
        if raw_peers is not None and not isinstance(raw_peers, list):
            raise ManifestError(f"{where}: {peer_key} must be a list")
        peers: tuple[Peer, ...] | None = None
        if raw_peers:
            peers = tuple(Peer.from_value(item, f"{where}.{peer_key}[{index}]") for index, item in enumerate(raw_peers))
        raw_ports = value.get("ports")
        if raw_ports is not None and not isinstance(raw_ports, list):
            raise ManifestError(f"{where}: ports must be a list")
        ports: tuple[PortRule, ...] | None = None
        if raw_ports:
            ports = tuple(
                PortRule.from_value(item, f"{where}.ports[{index}]") for index, item in enumerate(raw_ports)
            )
        return cls(peers, ports)

    @property
    def allows_any_peer(self) -> bool:
        return self.peers is None or any(peer.is_any for peer in self.peers)


@dataclass(frozen=True, slots=True)
class Namespace:
    name: str
    labels: dict[str, str] = field(default_factory=dict)
    source: str = ""
    line: int = 0


@dataclass(frozen=True, slots=True)
class Workload:
    name: str
    namespace: str
    labels: dict[str, str] = field(default_factory=dict)
    ports: tuple[tuple[str, str, int], ...] = ()
    source: str = ""
    line: int = 0

    @property
    def id(self) -> str:
        return f"{self.namespace}/{self.name}"

    def named_port(self, name: str, protocol: str) -> int | None:
        for port_name, port_protocol, number in self.ports:
            if port_name == name and port_protocol == protocol.upper():
                return number
        return None


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    name: str
    namespace: str
    pod_selector: LabelSelector
    ingress: tuple[PolicyRule, ...] | None
    egress: tuple[PolicyRule, ...] | None
    policy_types: frozenset[str]
    explicit_policy_types: bool
    source: str
    line: int

    @property
    def id(self) -> str:
        return f"{self.namespace}/{self.name}"

    @property
    def ingress_isolation(self) -> bool:
        return "Ingress" in self.policy_types

    @property
    def egress_isolation(self) -> bool:
        return "Egress" in self.policy_types

    def applies_to(self, workload: Workload) -> bool:
        return workload.namespace == self.namespace and self.pod_selector.matches(workload.labels)

    def rules_for(self, direction: str) -> tuple[PolicyRule, ...]:
        return self.ingress or () if direction == "Ingress" else self.egress or ()


@dataclass(frozen=True, slots=True)
class Topology:
    namespaces: dict[str, Namespace]
    workloads: dict[tuple[str, str], Workload]
    policies: dict[tuple[str, str], NetworkPolicy]
    sources: tuple[str, ...]
    ignored_kinds: tuple[str, ...]
