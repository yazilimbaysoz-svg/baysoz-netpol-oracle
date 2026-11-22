"""Audit rule and SARIF reporting tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json

from baysoz_netpol_oracle.findings import audit, render_text, to_json, to_sarif
from baysoz_netpol_oracle.loader import load_topology

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


def test_audit_detects_core_gaps(basic_fixture):
    findings = audit(load_topology([basic_fixture]))
    assert {item.rule_id for item in findings} == {"NPOL001", "NPOL002", "NPOL003", "NPOL004"}
    metadata = next(item for item in findings if item.rule_id == "NPOL003")
    assert "default/db" in metadata.detail
    assert metadata.line > 0
    assert metadata.source.endswith("basic.yaml")


def test_audit_evidence_is_rule_derived(basic_fixture):
    findings = audit(load_topology([basic_fixture]))
    broad = next(item for item in findings if item.rule_id == "NPOL004")
    assert "allow-api-egress" in broad.detail
    unrestricted = next(item for item in findings if item.rule_id == "NPOL001")
    assert any("no ingress NetworkPolicy" in item for item in unrestricted.evidence)


def test_sarif_payload(basic_fixture):
    topology = load_topology([basic_fixture])
    payload = to_sarif(audit(topology), topology.sources)
    assert payload["version"] == "2.1.0"
    driver = payload["runs"][0]["tool"]["driver"]
    assert ATTRIBUTION in driver["fullName"]
    assert len(driver["rules"]) == 4
    results = payload["runs"][0]["results"]
    assert results and all(item["locations"][0]["physicalLocation"]["region"]["startLine"] > 0 for item in results)
    assert payload["runs"][0]["properties"]["attribution"] == ATTRIBUTION
    assert json.loads(json.dumps(payload))["version"] == "2.1.0"


def test_json_and_text_reports_carry_attribution(basic_fixture):
    findings = audit(load_topology([basic_fixture]))
    assert to_json(findings)["attribution"] == ATTRIBUTION
    assert to_json(findings)["summary"]["errors"] == 3
    text = render_text(findings)
    assert ATTRIBUTION in text
    assert "NPOL003" in text
    assert "3 error(s)" in text


def test_hardened_manifest_has_no_findings(write_manifest):
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: isolated
  namespace: default
  labels:
    app: isolated
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolated-all
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: isolated
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 8080
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 443
"""
    findings = audit(load_topology([write_manifest("hardened.yaml", manifest)]))
    assert findings == ()
