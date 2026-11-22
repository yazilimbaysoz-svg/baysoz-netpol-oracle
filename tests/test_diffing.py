"""Reachability drift tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from pathlib import Path

from baysoz_netpol_oracle.diffing import diff, render_text, to_json
from baysoz_netpol_oracle.engine import METADATA_IP
from baysoz_netpol_oracle.loader import load_topology


def _candidate(tmp_path, basic_fixture):
    content = Path(basic_fixture).read_text(encoding="utf-8")
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(content + "        - port: 80\n", encoding="utf-8")
    return str(candidate)


def test_added_metadata_flow_is_detected(tmp_path, basic_fixture):
    candidate = _candidate(tmp_path, basic_fixture)
    changes = diff(load_topology([basic_fixture]), load_topology([candidate]))
    added_metadata = [
        item
        for item in changes
        if item.status == "ADDED"
        and item.flow.source == "default/api"
        and item.flow.destination == METADATA_IP
        and item.flow.port == 80
    ]
    assert added_metadata
    assert added_metadata[0].severity == "error"
    assert any("ALLOW default/allow-api-egress" in item for item in added_metadata[0].evidence)


def test_removed_flow_is_detected(tmp_path, basic_fixture):
    candidate = _candidate(tmp_path, basic_fixture)
    changes = diff(load_topology([candidate]), load_topology([basic_fixture]))
    assert any(item.status == "REMOVED" and item.flow.destination == METADATA_IP for item in changes)


def test_identical_revisions_have_no_drift(basic_fixture):
    topology = load_topology([basic_fixture])
    assert diff(topology, topology) == ()


def test_diff_rendering_includes_attribution(tmp_path, basic_fixture):
    candidate = _candidate(tmp_path, basic_fixture)
    changes = diff(load_topology([basic_fixture]), load_topology([candidate]))
    payload = to_json(changes)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["summary"]["added"] > 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in render_text(changes)
    assert json.loads(json.dumps(payload))["summary"]["added"] > 0
