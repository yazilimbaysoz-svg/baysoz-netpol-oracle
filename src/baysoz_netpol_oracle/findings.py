"""Audit findings, SARIF 2.1.0 emission and human-readable reports.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass

from . import __version__
from .engine import METADATA_IP, Endpoint, query
from .loader import ATTRIBUTION
from .model import NetworkPolicy, Topology, Workload

RULE_CATALOG: dict[str, tuple[str, str]] = {
    "NPOL001": (
        "Unrestricted ingress",
        "A workload is not selected by any ingress NetworkPolicy and accepts traffic from any source.",
    ),
    "NPOL002": (
        "Unrestricted egress",
        "A workload is not selected by any egress NetworkPolicy and can reach arbitrary destinations.",
    ),
    "NPOL003": (
        "Cloud metadata endpoint reachable",
        "A workload can send TCP/80 traffic to the cloud instance metadata address 169.254.169.254.",
    ),
    "NPOL004": (
        "Any-source rule",
        "A policy rule explicitly permits every peer on its direction, widening the trusted boundary.",
    ),
    "NPOL005": (
        "Policy selects no workloads",
        "A NetworkPolicy podSelector matches no Pod in its namespace, so the policy has no effect.",
    ),
    "NPOL006": (
        "Unresolved named port",
        "A policy references a named port that is not declared by any workload it selects.",
    ),
    "NPOL007": (
        "Implicit ingress-only isolation",
        "A policy has no rules and no explicit policyTypes; Kubernetes applies default-deny ingress only.",
    ),
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    level: str
    title: str
    detail: str
    source: str
    line: int
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "ruleId": self.rule_id,
            "level": self.level,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "line": self.line,
            "evidence": list(self.evidence),
        }


def _workloads(topology: Topology) -> list[Workload]:
    return sorted(topology.workloads.values(), key=lambda workload: workload.id)


def _policies(topology: Topology) -> list[NetworkPolicy]:
    return sorted(topology.policies.values(), key=lambda policy: policy.id)


def audit(topology: Topology) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    external = Endpoint.ip("203.0.113.10")

    for workload in _workloads(topology):
        ingress_policies = [
            policy.id
            for policy in topology.policies.values()
            if policy.ingress_isolation and policy.applies_to(workload)
        ]
        if not ingress_policies:
            decision = query(topology, external, Endpoint.workload(workload.namespace, workload.name), 443, "TCP")
            findings.append(
                Finding(
                    "NPOL001",
                    "error",
                    RULE_CATALOG["NPOL001"][0],
                    f"{workload.id} accepts TCP/443 from any source because no ingress policy selects it.",
                    workload.source,
                    workload.line,
                    decision.ingress.evidence,
                )
            )
        egress_policies = [
            policy.id
            for policy in topology.policies.values()
            if policy.egress_isolation and policy.applies_to(workload)
        ]
        if not egress_policies:
            decision = query(topology, Endpoint.workload(workload.namespace, workload.name), external, 443, "TCP")
            findings.append(
                Finding(
                    "NPOL002",
                    "error",
                    RULE_CATALOG["NPOL002"][0],
                    f"{workload.id} can reach arbitrary destinations because no egress policy selects it.",
                    workload.source,
                    workload.line,
                    decision.egress.evidence,
                )
            )
        metadata = query(
            topology,
            Endpoint.workload(workload.namespace, workload.name),
            Endpoint.ip(METADATA_IP),
            80,
            "TCP",
        )
        if metadata.allowed:
            findings.append(
                Finding(
                    "NPOL003",
                    "error",
                    RULE_CATALOG["NPOL003"][0],
                    f"{workload.id} can reach {METADATA_IP}:80/TCP; enforce an explicit egress allowlist.",
                    workload.source,
                    workload.line,
                    metadata.egress.evidence,
                )
            )

    for policy in _policies(topology):
        selected = [
            workload
            for workload in topology.workloads.values()
            if policy.namespace == workload.namespace and policy.pod_selector.matches(workload.labels)
        ]
        if not selected:
            findings.append(
                Finding(
                    "NPOL005",
                    "warning",
                    RULE_CATALOG["NPOL005"][0],
                    f"{policy.id} podSelector {policy.pod_selector.describe()} matches no Pod.",
                    policy.source,
                    policy.line,
                )
            )
        if not policy.explicit_policy_types and policy.ingress is None and policy.egress is None:
            findings.append(
                Finding(
                    "NPOL007",
                    "note",
                    RULE_CATALOG["NPOL007"][0],
                    f"{policy.id} has no rules; Kubernetes infers policyTypes [Ingress] only.",
                    policy.source,
                    policy.line,
                )
            )
        seen_named_ports: set[str] = set()
        for direction in ("Ingress", "Egress"):
            for index, rule in enumerate(policy.rules_for(direction)):
                if rule.allows_any_peer:
                    findings.append(
                        Finding(
                            "NPOL004",
                            "warning",
                            RULE_CATALOG["NPOL004"][0],
                            f"{policy.id} {direction.lower()} rule {index} permits any peer.",
                            policy.source,
                            policy.line,
                            (f"ports: {'all' if rule.ports is None else rule.ports}",),
                        )
                    )
                for port_rule in rule.ports or ():
                    if not isinstance(port_rule.port, str) or port_rule.port in seen_named_ports:
                        continue
                    seen_named_ports.add(port_rule.port)
                    declared = any(
                        workload.named_port(port_rule.port, port_rule.protocol) is not None
                        for workload in selected
                    )
                    if declared:
                        continue
                    findings.append(
                        Finding(
                            "NPOL006",
                            "warning",
                            RULE_CATALOG["NPOL006"][0],
                            f"{policy.id} references named port {port_rule.port!r} ({port_rule.protocol}) "
                            "that no selected workload declares.",
                            policy.source,
                            policy.line,
                        )
                    )
    return tuple(sorted(findings, key=lambda item: (item.rule_id, item.source, item.line, item.detail)))


def _severity_order(level: str) -> int:
    return {"error": 0, "warning": 1, "note": 2}.get(level, 3)


def render_text(findings: tuple[Finding, ...]) -> str:
    lines = [f"baysoz-netpol-oracle {__version__} — {ATTRIBUTION}", ""]
    if not findings:
        lines.append("No findings: all workloads have directional isolation and no broad rule was detected.")
    for finding in sorted(findings, key=lambda item: (_severity_order(item.level), item.rule_id, item.detail)):
        lines.append(f"[{finding.level.upper():7}] {finding.rule_id} {finding.title}")
        lines.append(f"          {finding.detail}")
        lines.append(f"          location: {finding.source}:{finding.line}")
        for item in finding.evidence:
            lines.append(f"          evidence: {item}")
    errors = sum(item.level == "error" for item in findings)
    warnings = sum(item.level == "warning" for item in findings)
    notes = sum(item.level == "note" for item in findings)
    lines.extend(["", f"Summary: {errors} error(s), {warnings} warning(s), {notes} note(s).", ATTRIBUTION])
    return "\n".join(lines)


def to_json(findings: tuple[Finding, ...]) -> dict[str, object]:
    return {
        "tool": "baysoz-netpol-oracle",
        "version": __version__,
        "attribution": ATTRIBUTION,
        "summary": {
            "errors": sum(item.level == "error" for item in findings),
            "warnings": sum(item.level == "warning" for item in findings),
            "notes": sum(item.level == "note" for item in findings),
        },
        "findings": [item.as_dict() for item in findings],
    }


def to_sarif(findings: tuple[Finding, ...], sources: tuple[str, ...] = ()) -> dict[str, object]:
    used_rules = sorted({item.rule_id for item in findings})
    rules = []
    for rule_id in used_rules:
        title, description = RULE_CATALOG[rule_id]
        rules.append(
            {
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": "warning"},
            }
        )
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.level,
                "message": {"text": f"{finding.title}: {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.source},
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
                "properties": {"evidence": list(finding.evidence)},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-netpol-oracle",
                        "fullName": f"baysoz-netpol-oracle {__version__} — {ATTRIBUTION}",
                        "version": __version__,
                        "informationUri": "https://github.com/yazilimbaysoz-svg/baysoz-netpol-oracle",
                        "rules": rules,
                    }
                },
                "artifacts": [{"location": {"uri": source}} for source in sources],
                "results": results,
                "properties": {"attribution": ATTRIBUTION},
            }
        ],
    }


__all__ = ["Finding", "RULE_CATALOG", "audit", "render_text", "to_json", "to_sarif"]
