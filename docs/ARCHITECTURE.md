# Architecture

Baysöz Labs <baysozlabs@proton.me>

## System shape

```text
paths (files/directories)
        │
        ▼
StrictSafeLoader (PyYAML SafeLoader subclass)
  • rejects duplicate mapping keys (ambiguous policy is a security defect)
  • records 1-based source line for each document
        │
        ▼
loader.load_topology()
  • kind: Namespace / Pod / NetworkPolicy / List
  • implicit namespaces with empty labels for undeclared namespaces
  • strict validation of selectors, ipBlock CIDRs, ports and policyTypes
        │
        ▼
model.Topology
  namespaces: name -> labels
  workloads:  (namespace, name) -> labels + named ports
  policies:   (namespace, name) -> selectors + rules + explicit policyTypes
        │
        ├──────────────► engine.query(source, destination, port, protocol)
        │                  ingress trace ∧ egress trace → Decision + evidence
        │
        ├──────────────► findings.audit(topology)
        │                  NPOL001…NPOL007 → text / JSON / SARIF 2.1.0
        │
        └──────────────► diffing.diff(before, after)
                           probe matrix → added / removed flows
```

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `model.py` | Frozen dataclasses for selectors, peers, ports, policies, workloads and topology |
| `loader.py` | Strict YAML parsing, line tracking, multi-doc and `List` support, validation |
| `engine.py` | Exact-flow authorization with deterministic, human-readable evidence |
| `findings.py` | Seven audit rules, severity model, SARIF emission |
| `diffing.py` | Before/after reachability matrix and drift classification |
| `cli.py` | `audit`, `query`, `diff` commands; exit codes for CI gating |

## Authorization algorithm

For a flow `S → D` on `protocol/P`:

1. Resolve endpoints as workload references or literal IPs. Unknown workloads are hard errors.
2. **Ingress side:** collect policies in `D.namespace` selecting `D` with `Ingress` isolation.
   None → unrestricted. Otherwise require one rule whose ports match `P/protocol` (named ports
   resolve on `D`) and whose peer matches `S`.
3. **Egress side:** collect policies in `S.namespace` selecting `S` with `Egress` isolation.
   None → unrestricted. Otherwise require one rule whose ports match `P/protocol` and whose peer
   matches `D`.
4. Admit only if both sides are unrestricted or have a matching allow rule.
5. Emit the exact policy ID, rule index, peer index and reason for every allow; on denial, emit the
   isolation count plus the port constraints that failed.

Peer matching rules follow the Kubernetes API:

- `from`/`to` omitted or empty → every peer, including arbitrary IPs.
- `podSelector` alone → selected pods in the policy's own namespace.
- `namespaceSelector` alone → all pods in namespaces whose labels match.
- Both → namespace labels **and** pod labels must match.
- `ipBlock` → address in CIDR and not in any `except` range.
- Empty peer object `{}` → every peer.

`policyTypes` inference: if omitted, a policy with `ingress` rules isolates Ingress; a policy with
`egress` rules isolates Egress; a policy with neither isolates Ingress only.

## Determinism

- Workloads, policies, rules and findings are sorted by stable IDs.
- IP addresses are normalized with `ipaddress`; CIDRs must be canonical.
- No clock, randomness, environment lookup, cluster API call or network I/O is used at runtime.
- The same manifest bytes always produce byte-identical text, JSON and SARIF output.

## Complexity

Let `P` be policies, `R` rules per policy, `W` workloads and `K` probe ports. A single query is
`O(P·R)`; the drift probe matrix is `O((W + 3)²·K·P·R)` with `K = 4`. The matrix is bounded by
manifest size and needs no external services.

## Security properties

- YAML is parsed with a SafeLoader subclass; no tags can instantiate arbitrary Python objects.
- Duplicate YAML keys are rejected: an ambiguous key must never silently change a policy.
- No subprocesses, sockets, credential reads or dynamic code execution.
- Findings point to real source lines; evidence is derived only from parsed manifests.

Baysöz Labs <baysozlabs@proton.me>
