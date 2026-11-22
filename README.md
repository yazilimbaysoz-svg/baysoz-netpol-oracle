# Baysöz Labs — baysoz-netpol-oracle

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-netpol-oracle/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-netpol-oracle/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange.svg)](docs/ARCHITECTURE.md)
[![Maintainer](https://img.shields.io/badge/maintained%20by-Bays%C3%B6z%20Labs-purple.svg)](mailto:baysozlabs@proton.me)

**Offline Kubernetes NetworkPolicy reachability oracle and SARIF CI gate.**
Built and maintained by **Baysöz Labs** <baysozlabs@proton.me>.

`netpol-oracle` answers a question that `kubectl describe` cannot answer before apply time:
*given every NetworkPolicy, Namespace label, Pod label and named port in this manifest set, is this exact
flow admitted — and which rule admitted it?* It needs no cluster, no daemon, no network and no service.

## Why it exists

NetworkPolicy is deny-by-default **only for pods that a policy selects**. Two policies combine by union.
`namespaceSelector` + `podSelector` is an AND across namespaces. Empty selectors mean "all". Named ports
resolve against the destination pod. Missing these details is how "we have default-deny" becomes "the
database is reachable from every namespace". Recent ecosystem evidence: Prowler's
`[Feature Request] Kubernetes NetworkPolicy Coverage Analysis` (2026-11-21) and Cilium's
`Certain network policies may inadvertently select non-Endpoint identities` (2026-07-07).
See [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) for the full live-search justification.

## Install

Python 3.13+ and `uv` are the only prerequisites.

```bash
uv venv
uv pip install -e .
uv run netpol-oracle --version
# netpol-oracle 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
```

## CLI

```bash
# Enterprise CI gate: fails on error-level findings, emits SARIF for code scanning.
uv run netpol-oracle audit manifests/ --format sarif --fail-on error > netpol.sarif

# Deterministic flow query with the exact allow rule named.
uv run netpol-oracle query manifests/ \
  --src default/api --dst 169.254.169.254 --port 80 --protocol TCP --expect deny

# Pre-merge reachability drift: fail when a candidate opens any new flow.
uv run netpol-oracle diff manifests/before/ manifests/after/ --fail-on-added
```

### Real CLI output

```text
$ uv run netpol-oracle query tests/fixtures/basic.yaml \
    --src default/api --dst default/db --port 5432 --protocol TCP
baysoz-netpol-oracle 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

Flow:    default/api -> default/db TCP/5432
Verdict: DENIED
Summary: DENIED: ingress authorization check(s) have no matching allow rule

Ingress evaluation:
  - no ingress rule matched; 1 policy(ies) isolate default/db
  - default/db-ingress ingress rule 0 requires TCP/8080
Egress evaluation:
  - ALLOW default/allow-api-egress egress rule 0 peer 0: any destination; port TCP/5432 matches TCP/5432 or TCP/8080

Baysöz Labs <baysozlabs@proton.me>
```

The header/footer attribution is emitted by every text command; JSON and SARIF payloads carry it in
`attribution` / `tool.driver.fullName` fields. `--help`, subcommand help and `--version` also carry it.

## What it detects

| Rule | Severity | Meaning |
| --- | --- | --- |
| NPOL001 | error | Workload has no ingress policy — all sources accepted |
| NPOL002 | error | Workload has no egress policy — arbitrary destinations accepted |
| NPOL003 | error | Cloud metadata address `169.254.169.254:80/TCP` is reachable |
| NPOL004 | warning | Rule explicitly permits every peer |
| NPOL005 | warning | Policy podSelector matches no workload |
| NPOL006 | warning | Named port in a rule is not declared by selected workloads |
| NPOL007 | note | Empty policy infers ingress-only isolation (Kubernetes semantics) |

## Architecture

```text
YAML files ──> StrictSafeLoader ──> Topology ──> Reachability engine ──> Findings
                  (duplicate keys)   (pods/ns/    (ingress AND egress)    ├─ text
                                      policies)                          ├─ JSON
                                                                         └─ SARIF 2.1.0
                                              diff(before, after) ──> added/removed flows
```

The engine evaluates both directions independently and admits a flow only when ingress **and** egress
authorization succeed. Full model and algorithms: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest && uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Documentation

- [Market research](docs/MARKET_RESEARCH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Delivery plan](PLAN.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Attribution

Baysöz Labs <baysozlabs@proton.me> — https://github.com
