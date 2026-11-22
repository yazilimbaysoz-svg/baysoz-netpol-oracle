"""Deterministic reachability drift comparison between manifest revisions.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass

from . import __version__
from .engine import METADATA_IP, Endpoint, query
from .loader import ATTRIBUTION
from .model import Topology

PROBE_ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint.ip(METADATA_IP),
    Endpoint.ip("10.96.0.10"),
    Endpoint.ip("203.0.113.10"),
)
PROBE_TRAFFIC: tuple[tuple[int, str], ...] = ((80, "TCP"), (443, "TCP"), (53, "UDP"), (5432, "TCP"))
SENSITIVE_PORTS = frozenset({22, 3306, 5432})


@dataclass(frozen=True, slots=True)
class Flow:
    source: str
    destination: str
    port: int
    protocol: str

    @property
    def key(self) -> tuple[str, str, int, str]:
        return (self.source, self.destination, self.port, self.protocol)

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
        }


@dataclass(frozen=True, slots=True)
class FlowChange:
    status: str
    flow: Flow
    severity: str
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "severity": self.severity,
            "flow": self.flow.as_dict(),
            "evidence": list(self.evidence),
        }


def _severity(flow: Flow) -> str:
    if flow.destination == METADATA_IP or flow.port in SENSITIVE_PORTS:
        return "error"
    return "warning"


def _available(topology: Topology, endpoint: Endpoint) -> bool:
    return endpoint.is_ip or (endpoint.namespace, endpoint.pod) in topology.workloads


def _endpoints(*topologies: Topology) -> tuple[Endpoint, ...]:
    workloads = sorted(
        {key for topology in topologies for key in topology.workloads},
        key=lambda key: f"{key[0]}/{key[1]}",
    )
    return tuple(Endpoint.workload(namespace, name) for namespace, name in workloads) + PROBE_ENDPOINTS


def _allowed_flows(topology: Topology, endpoints: tuple[Endpoint, ...]) -> dict[Flow, object]:
    allowed: dict[Flow, object] = {}
    for source in endpoints:
        if not _available(topology, source):
            continue
        for destination in endpoints:
            if destination.is_ip and source.is_ip:
                continue
            if source.key == destination.key or not _available(topology, destination):
                continue
            for port, protocol in PROBE_TRAFFIC:
                decision = query(topology, source, destination, port, protocol)
                if decision.allowed:
                    allowed[Flow(source.key, destination.key, port, protocol)] = decision
    return allowed


def diff(baseline: Topology, candidate: Topology) -> tuple[FlowChange, ...]:
    endpoints = _endpoints(baseline, candidate)
    before = _allowed_flows(baseline, endpoints)
    after = _allowed_flows(candidate, endpoints)
    changes: list[FlowChange] = []
    for flow in sorted(set(before) | set(after), key=lambda item: item.key):
        if flow in before and flow in after:
            continue
        added = flow in after
        decision = after[flow] if added else before[flow]
        evidence = tuple(decision.ingress.evidence + decision.egress.evidence)
        changes.append(FlowChange("ADDED" if added else "REMOVED", flow, _severity(flow), evidence))
    return tuple(changes)


def render_text(changes: tuple[FlowChange, ...]) -> str:
    lines = [f"baysoz-netpol-oracle {__version__} — {ATTRIBUTION}", ""]
    if not changes:
        lines.append("No reachability drift detected between the two manifest revisions.")
    for change in sorted(changes, key=lambda item: (item.status, item.severity, item.flow.key)):
        flow = change.flow
        lines.append(
            f"[{change.status:7}] {change.severity.upper():7} {flow.source} -> {flow.destination} "
            f"{flow.protocol}/{flow.port}"
        )
        for item in change.evidence:
            lines.append(f"          evidence: {item}")
    added = sum(item.status == "ADDED" for item in changes)
    removed = sum(item.status == "REMOVED" for item in changes)
    lines.extend(["", f"Summary: {added} added flow(s), {removed} removed flow(s).", ATTRIBUTION])
    return "\n".join(lines)


def to_json(changes: tuple[FlowChange, ...]) -> dict[str, object]:
    return {
        "tool": "baysoz-netpol-oracle",
        "version": __version__,
        "attribution": ATTRIBUTION,
        "summary": {
            "added": sum(item.status == "ADDED" for item in changes),
            "removed": sum(item.status == "REMOVED" for item in changes),
        },
        "changes": [item.as_dict() for item in changes],
    }


__all__ = ["Flow", "FlowChange", "diff", "render_text", "to_json"]
