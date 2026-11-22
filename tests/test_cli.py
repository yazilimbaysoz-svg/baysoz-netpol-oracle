"""CLI contract and CI exit-code tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_netpol_oracle.cli import main

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


def test_version_and_help_carry_attribution(capsys):
    for argument in ("--version", "--help"):
        with pytest.raises(SystemExit) as exc:
            main([argument])
        assert exc.value.code == 0
        assert ATTRIBUTION in capsys.readouterr().out


def test_subcommand_help_carries_attribution(capsys):
    for command in ("audit", "query", "diff"):
        with pytest.raises(SystemExit) as exc:
            main([command, "--help"])
        assert exc.value.code == 0
        assert ATTRIBUTION in capsys.readouterr().out


def test_audit_sarif_and_fail_on(basic_fixture, capsys):
    assert main(["audit", basic_fixture, "--format", "sarif", "--fail-on", "none"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert ATTRIBUTION in payload["runs"][0]["tool"]["driver"]["fullName"]
    assert main(["audit", basic_fixture, "--fail-on", "error"]) == 1
    capsys.readouterr()
    assert main(["audit", basic_fixture, "--format", "json", "--fail-on", "warning"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == ATTRIBUTION


def test_query_expectations(basic_fixture, capsys):
    command = ["query", basic_fixture, "--src", "default/api", "--dst", "169.254.169.254", "--port", "80"]
    assert main(command + ["--expect", "deny"]) == 0
    assert ATTRIBUTION in capsys.readouterr().out
    assert main(command + ["--expect", "allow"]) == 2
    captured = capsys.readouterr()
    assert "expected allow" in captured.err
    assert ATTRIBUTION in captured.err
    db_command = ["query", basic_fixture, "--src", "default/api", "--dst", "default/db", "--port", "5432"]
    assert main(db_command) == 0
    assert "Verdict: DENIED" in capsys.readouterr().out


def test_query_json_contains_evidence(basic_fixture, capsys):
    command = [
        "query",
        basic_fixture,
        "--src",
        "default/api",
        "--dst",
        "default/db",
        "--port",
        "8080",
        "--format",
        "json",
    ]
    assert main(command) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == ATTRIBUTION
    assert payload["verdict"] == "ALLOWED"
    assert any("ALLOW default/db-ingress ingress rule 0" in item for item in payload["ingress"]["evidence"])


def test_bad_input_exits_two_with_attribution(basic_fixture, capsys):
    assert main(["query", basic_fixture, "--src", "bogus", "--dst", "8.8.8.8"]) == 2
    assert ATTRIBUTION in capsys.readouterr().err


def test_diff_gate(tmp_path, basic_fixture, capsys):
    content = Path(basic_fixture).read_text(encoding="utf-8")
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(content + "        - port: 80\n", encoding="utf-8")
    assert main(["diff", basic_fixture, str(candidate), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["added"] > 0
    assert main(["diff", basic_fixture, str(candidate), "--fail-on-added"]) == 1
    assert ATTRIBUTION in capsys.readouterr().out
