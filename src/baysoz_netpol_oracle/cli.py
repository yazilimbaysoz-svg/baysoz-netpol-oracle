"""Command-line interface for the offline NetworkPolicy reachability gate.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .diffing import diff, render_text as render_diff, to_json as diff_to_json
from .engine import Endpoint, query
from .findings import audit, render_text as render_audit, to_json as audit_to_json, to_sarif
from .loader import ATTRIBUTION, load_topology
from .model import ManifestError

PROG = "netpol-oracle"
HEADER = f"baysoz-netpol-oracle {__version__} — {ATTRIBUTION}"
EPILOG = f"""Examples:
  netpol-oracle audit manifests/ --format sarif --fail-on error
  netpol-oracle query manifests/ --src default/api --dst 169.254.169.254 --port 80
  netpol-oracle diff manifests/before.yaml manifests/after.yaml --fail-on-added

Attribution: {ATTRIBUTION}
"""


class AttributionArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n{ATTRIBUTION}\n")


def _parser() -> AttributionArgumentParser:
    parser = AttributionArgumentParser(
        prog=PROG,
        description=f"Offline Kubernetes NetworkPolicy reachability oracle and SARIF CI gate. {ATTRIBUTION}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__} — {ATTRIBUTION}",
    )
    commands = parser.add_subparsers(dest="command", required=True, parser_class=AttributionArgumentParser)
    audit_parser = commands.add_parser(
        "audit",
        help="audit manifests for isolation gaps and emit text, JSON or SARIF",
        description=f"Audit Kubernetes manifests for NetworkPolicy coverage gaps. {ATTRIBUTION}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit_parser.add_argument("paths", nargs="+", help="YAML files or directories to analyze")
    audit_parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    audit_parser.add_argument("--fail-on", choices=("none", "error", "warning"), default="error")
    query_parser = commands.add_parser(
        "query",
        help="evaluate one admitted or denied flow with full rule evidence",
        description=f"Evaluate a concrete flow against effective NetworkPolicy rules. {ATTRIBUTION}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    query_parser.add_argument("paths", nargs="+", help="YAML files or directories to analyze")
    query_parser.add_argument("--src", required=True, help="namespace/pod or an IP address")
    query_parser.add_argument("--dst", required=True, help="namespace/pod or an IP address")
    query_parser.add_argument("--port", type=int, default=443)
    query_parser.add_argument("--protocol", choices=("TCP", "UDP", "SCTP"), default="TCP")
    query_parser.add_argument("--format", choices=("text", "json"), default="text")
    query_parser.add_argument("--expect", choices=("allow", "deny"), help="fail with exit code 2 on mismatch")
    diff_parser = commands.add_parser(
        "diff",
        help="compare reachability between a baseline and candidate manifest set",
        description=f"Compare effective NetworkPolicy reachability across revisions. {ATTRIBUTION}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff_parser.add_argument("baseline", help="baseline YAML file or directory")
    diff_parser.add_argument("candidate", help="candidate YAML file or directory")
    diff_parser.add_argument("--format", choices=("text", "json"), default="text")
    diff_parser.add_argument("--fail-on-added", action="store_true", help="exit 1 when new flows appear")
    return parser


def _dump(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def _render_query(decision: object) -> str:
    lines = [
        HEADER,
        "",
        f"Flow:    {decision.source} -> {decision.destination} {decision.protocol}/{decision.port}",
        f"Verdict: {decision.verdict}",
        f"Summary: {decision.summary}",
        "",
        "Ingress evaluation:",
    ]
    lines.extend(f"  - {item}" for item in decision.ingress.evidence)
    lines.append("Egress evaluation:")
    lines.extend(f"  - {item}" for item in decision.egress.evidence)
    lines.extend(["", ATTRIBUTION])
    return "\n".join(lines)


def _query_json(decision: object) -> str:
    payload = {
        "tool": "baysoz-netpol-oracle",
        "version": __version__,
        "attribution": ATTRIBUTION,
        "source": decision.source,
        "destination": decision.destination,
        "port": decision.port,
        "protocol": decision.protocol,
        "verdict": decision.verdict,
        "summary": decision.summary,
        "ingress": {
            "isolated": decision.ingress.isolated,
            "allowed": decision.ingress.allowed,
            "policies": list(decision.ingress.policies),
            "evidence": list(decision.ingress.evidence),
        },
        "egress": {
            "isolated": decision.egress.isolated,
            "allowed": decision.egress.allowed,
            "policies": list(decision.egress.policies),
            "evidence": list(decision.egress.evidence),
        },
    }
    return _dump(payload)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            topology = load_topology(args.paths)
            findings = audit(topology)
            if args.format == "sarif":
                print(_dump(to_sarif(findings, topology.sources)))
            elif args.format == "json":
                print(_dump(audit_to_json(findings)))
            else:
                print(render_audit(findings))
            if args.fail_on == "error" and any(item.level == "error" for item in findings):
                return 1
            if args.fail_on == "warning" and findings:
                return 1
            return 0
        if args.command == "query":
            topology = load_topology(args.paths)
            decision = query(
                topology,
                Endpoint.parse(args.src),
                Endpoint.parse(args.dst),
                args.port,
                args.protocol,
            )
            print(_render_query(decision) if args.format == "text" else _query_json(decision))
            actual = "allow" if decision.allowed else "deny"
            if args.expect and actual != args.expect:
                print(f"error: expected {args.expect}, got {actual}", file=sys.stderr)
                print(ATTRIBUTION, file=sys.stderr)
                return 2
            return 0
        topology_before = load_topology([args.baseline])
        topology_after = load_topology([args.candidate])
        changes = diff(topology_before, topology_after)
        print(_dump(diff_to_json(changes)) if args.format == "json" else render_diff(changes))
        if args.fail_on_added and any(item.status == "ADDED" for item in changes):
            return 1
        return 0
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(ATTRIBUTION, file=sys.stderr)
        return 2


__all__ = ["main"]
