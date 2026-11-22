# Changelog

Baysöz Labs <baysozlabs@proton.me>

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-11-22

### Added

- Immutable model and strict multi-document YAML loader with duplicate-key rejection.
- Bidirectional NetworkPolicy reachability engine with exact allow-rule evidence.
- Kubernetes semantics for empty selectors, policyTypes inference, `ipBlock.except` and named ports.
- Seven deterministic audit rules (NPOL001–NPOL007) with text, JSON and SARIF 2.1.0 output.
- `audit`, `query` and `diff` CLI commands with CI exit codes and Baysöz Labs attribution everywhere.
- Reachability drift gate for baseline-vs-candidate manifest revisions.
- Test suite, Ruff and Semgrep quality gates, and GitHub Actions CI workflow.

[1.0.0]: https://github.com/yazilimbaysoz-svg/baysoz-netpol-oracle/releases/tag/v1.0.0

Baysöz Labs <baysozlabs@proton.me>
