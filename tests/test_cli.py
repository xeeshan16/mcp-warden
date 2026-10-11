from __future__ import annotations

from pathlib import Path

import pytest

from mcp_warden.__main__ import main

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"


def test_check_valid_policy(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(EXAMPLE)]) == 0
    assert "ok:" in capsys.readouterr().out


def test_check_dry_run_decision(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        ["check", str(EXAMPLE), "--agent", "bot", "--server", "github", "--tool", "delete_repo"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "deny: bot -> github/delete_repo (rule never-destructive" in out


def test_check_invalid_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 9\n", encoding="utf-8")
    assert main(["check", str(bad)]) == 1
    assert "error:" in capsys.readouterr().err
