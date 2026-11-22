# Market research — why a NetworkPolicy reachability oracle

Baysöz Labs <baysozlabs@proton.me>

Research date: 2026-11-22. Method: live `gh search repos` / `gh search issues` plus inspection of
`/home/runner/work/_temp/existing-repos.json`. All counts and dates below are the values returned by
the GitHub CLI during this session.

## 1. Signal from live GitHub searches

### High-star ecosystem (demand is real, not hypothetical)

| Repository | Stars | Last push | Relevance |
| --- | ---: | --- | --- |
| `aquasecurity/trivy` | 39,613 | 2026-11-20 | Vulnerabilities/misconfigurations; no exact-flow NetworkPolicy oracle |
| `cilium/cilium` | 25,881 | 2026-11-22 | eBPF enforcement; policy semantics live here, but requires a running datapath to test |
| `kubescape/kubescape` | 11,971 | 2026-11-21 | Cluster posture/framework scanning; not a bidirectional flow prover |
| `falcosecurity/falco` | 9,599 | 2026-11-20 | Runtime detection; post-hoc, not pre-merge |
| `kyverno/kyverno` | 8,370 | 2026-11-22 | Policy-as-code admission; validates shapes, not reachability |
| `aquasecurity/kube-bench` | 8,264 | 2026-11-16 | CIS benchmark checks; static checklist, not policy graph analysis |
| `ahmetb/kubernetes-network-policy-recipes` | 6,195 | 2025-02-07 | Recipes show the need; users still must reason about combinations manually |
| `cilium/hubble` | 4,396 | 2026-11-16 | Observability after deployment; cannot gate a pull request |
| `open-policy-agent/gatekeeper` | 4,302 | 2026-11-21 | Admission enforcement; no off-cluster what-if flow engine |
| `kubernetes-sigs/network-policy-api` | 94 | 2026 | AdminNetworkPolicy evolution; complexity is increasing, not decreasing |
| `IBM/network-config-analyzer` | 18 | — | Closest conceptual prior art, but narrow and not a CI SARIF gate |

Commands used (abridged):

```bash
gh search repos 'kubernetes security stars:>2000 pushed:>2026-06-01' --limit 20 ...
gh search repos networkpolicy --limit 15 ...
gh search repos 'kubernetes CRD diff' --limit 10 ...
```

### Open issues (the pain is current)

| Repository | Opened | Issue |
| --- | --- | --- |
| `prowler-cloud/prowler` | 2026-11-21 | `[Feature Request] Kubernetes NetworkPolicy Coverage Analysis` |
| `cilium/cilium` | 2026-07-07 | `Certain network policies may inadvertently select non-Endpoint identities` |
| `cilium/cilium` | 2026-11-17 | `Update Kubernetes ClusterNetworkPolicy to v1beta1` |
| `prowler-cloud/prowler` | 2026-10-15 | `aks_network_policy_enabled passes AKS clusters without a network policy` |
| `JiRaska/open-bank-oss` | 2026-11-22 | `Agent-plane workloads without an egress NetworkPolicy` |
| `TrueRelevance/hephaisto` | 2026-10-12 | `NetworkPolicy enforcement is unproven` |

A representative live query:

```bash
gh search issues 'network policy' --repo prowler-cloud/prowler --state open --limit 6 ...
gh search issues networkpolicy --limit 20 ...
```

The common theme: teams believe they are covered, but nobody can prove an exact packet path from
manifests alone. Posture scanners answer "is a policy present?"; runtime tools answer "what happened?".
Neither answers "will this PR admit `api -> 169.254.169.254:80`?" before merge.

## 2. Gap analysis against this factory's prior work

The 19 existing project names were inventoried from `existing-repos.json`. The closest neighbours and
the hard boundary between them and this project:

- `baysoz-routegate` — Kubernetes **Gateway API L7 route** precedence/shadowing. This project is
  **L3/L4 pod-to-pod and pod-to-IP reachability** with bidirectional policy authorization.
- `bolaforge` — OpenAPI BOLA/IDOR test-plan generation. Different layer (HTTP authorization, not CNI).
- `planradius` / `baysoz-actionlock` — Terraform blast radius and GitHub Actions dependency drift.
  No NetworkPolicy semantics, named ports, `ipBlock.except` or cloud metadata probes.
- `baysoz-burnlattice` — SLO burn-rate alerts. Operational, not admission/CNI.
- `baysoz-otelgate` / `baysoz-cardinalis` — telemetry configuration and cardinality.
- `baysoz-logmask` / `baysoz-josegate` — log PII masking and JOSE algorithm confusion.
- `envpair` / `envlens` / `sec-audit-cli` / `redos-lint` — small config/lint utilities; explicitly
  out of scope for a deep production engine.

No existing project computes effective ingress ∧ egress authorization across multi-document manifests,
and none emits reachability drift as a CI gate. Adding this project increases coverage rather than
duplicating it.

## 3. Why this problem is technically deep

1. **Union across policies.** Isolation is per direction; a pod may be ingress-isolated by one policy
   and egress-isolated by another. Admission requires an allow in *both* isolated directions.
2. **Empty is dangerous.** An empty `podSelector` selects all pods in the namespace; an empty
   `namespaceSelector` selects all namespaces; an empty/omitted `from`/`to` matches every peer.
3. **Peers are heterogeneous.** `podSelector`, `namespaceSelector`, their conjunction and
   `ipBlock` with `except` require different evaluation paths.
4. **Named ports bind to the destination.** A rule naming `postgres` only matches if the target pod
   actually declares that name for the requested protocol.
5. **Inference traps.** Omitting `policyTypes` with no rules infers `[Ingress]` only, silently leaving
   egress unrestricted.
6. **CI usefulness.** Findings must carry stable rule IDs, source line numbers and SARIF 2.1.0 output;
   PR-to-PR reachability must be diffable, not just "policy changed".

## 4. Chosen solution

A Python 3.13+ CLI/library, `baysoz-netpol-oracle`, using only the standard library plus PyYAML.
It is deterministic, offline, single-binary-simple (`uv pip install -e .`), needs zero services and
zero local LLMs. The toolchain matches the factory's existing Python/`uv` conventions while targeting
a problem anchored by 25k–40k-star ecosystems and fresh 2026 issues.

Baysöz Labs <baysozlabs@proton.me>
