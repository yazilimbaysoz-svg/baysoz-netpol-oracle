"""Shared pytest helpers for the Baysöz Labs NetworkPolicy oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import pytest


@pytest.fixture
def write_manifest(tmp_path):
    def _write(name: str, content: str):
        path = tmp_path / name
        path.write_text(f"# Baysöz Labs <baysozlabs@proton.me>\n{content}", encoding="utf-8")
        return str(path)

    return _write


@pytest.fixture
def basic_fixture() -> str:
    from pathlib import Path

    return str(Path(__file__).parent / "fixtures" / "basic.yaml")
