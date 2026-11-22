# Security policy

Baysöz Labs <baysozlabs@proton.me>

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting vulnerabilities

Report security issues privately to **baysozlabs@proton.me**. Include a minimal manifest set, the
CLI command, the observed output and the expected output. Please do not open public issues for
exploitable defects.

## Threat model and mitigations

| Threat | Mitigation |
| --- | --- |
| Malicious YAML tags instantiating Python objects | `StrictSafeLoader` derives from `yaml.SafeLoader`; unsafe tags are rejected |
| Ambiguous policy via duplicate mapping keys | Duplicate keys raise a manifest error with line information |
| Malformed CIDR or `except` outside CIDR | Strict `ipaddress` validation rejects both |
| Silent permission widening after a PR | `diff --fail-on-added` classifies new flows as CI failures |
| Hidden metadata-service egress | NPOL003 probes `169.254.169.254:80/TCP` for every workload |
| Hallucinated evidence | Every evidence string is generated from a parsed policy/rule/peer with an index |
| Command injection / arbitrary code execution | No shell invocation, `eval`, `exec`, `pickle` or dynamic import of manifest data |
| Credential leakage | The tool never reads cluster credentials, kubeconfigs or environment secrets |

## Safe usage

The tool is read-only. Point it at trusted or untrusted manifest directories; it will not contact a
cluster. Use `--fail-on error` in CI and upload the SARIF output to code scanning. When using
`query --expect`, remember that a mismatch exits with code 2.

## Dependency policy

Runtime dependencies are limited to Python 3.13+ standard library and PyYAML. CI uses `uv` for
reproducible installs. Static analysis uses Ruff (`E,F,W,S,B`) and Semgrep (`p/default`).

## Attribution

Baysöz Labs <baysozlabs@proton.me>
