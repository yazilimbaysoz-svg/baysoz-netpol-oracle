# Delivery plan — baysoz-netpol-oracle

Baysöz Labs <baysozlabs@proton.me>

## Phase 1 — Research (complete)

- Inspected all 19 entries in `existing-repos.json` and excluded overlapping domains.
- Mined `gh search repos` and `gh search issues` on 2026-11-22.
- Selected NetworkPolicy reachability/coverage: fresh Prowler feature request (2026-11-21),
  active Cilium policy-selection defect (2026-07-07), and multi-thousand-star enforcement ecosystem.
- Evidence and gap analysis: `docs/MARKET_RESEARCH.md`.

## Phase 2 — Engine (complete)

- Immutable model of selectors, peers, ports, policies, namespaces and workloads.
- Strict multi-document YAML loader with duplicate-key rejection and line tracking.
- Bidirectional authorization evaluator with concrete evidence strings.
- Kubernetes semantics for empty selectors, policyTypes inference, named ports and `ipBlock.except`.

## Phase 3 — CI surface (complete)

- Seven deterministic audit rules with stable IDs and severities.
- Text, JSON and SARIF 2.1.0 renderers with explicit Baysöz Labs attribution.
- `audit`, `query` and `diff` commands; exit codes 0/1/2 for pass/gate/error.
- Reachability drift probe matrix for baseline-vs-candidate comparison.

## Phase 4 — Quality gates (complete)

- `uv venv && uv pip install -e . && uv pip install pytest`
- `uv run pytest -q`
- `ruff check --select E,F,W,S,B .`
- `semgrep --config p/default --error .`
- Iterate until every gate reports zero findings.

## Phase 5 — Supreme Grand Jury Tribunal (complete)

- Executed the built CLI against adversarial manifests: duplicate YAML keys, unsafe YAML tags,
  `ipBlock.except` boundaries, selector traps, named-port mismatch, empty-policy inference,
  metadata egress and reachability drift.
- Verified that every reported allow/deny cites a real parsed rule and that no output is stubbed.
- Result: **24 PASS / 0 FAIL — UNANIMOUS PASS**. Output is byte-identical across repeated runs.

## Phase 6 — Publication (complete)

- Published with `gh repo create yazilimbaysoz-svg/baysoz-netpol-oracle --public --source=. --remote=origin --push`.
- Wrote the factory result descriptor without touching other showcase workspace files.

## Acceptance criteria

1. All tests pass with zero skips and zero xfails.
2. Ruff and Semgrep report zero findings.
3. `--version`, `--help`, subcommand help, every text output and every structured payload contain
   `Baysöz Labs <baysozlabs@proton.me>`.
4. Every public file carries Baysöz Labs attribution; no legal entity suffixes are used.
5. No service, daemon, container runtime, cluster connection or local LLM is required.

Baysöz Labs <baysozlabs@proton.me>
