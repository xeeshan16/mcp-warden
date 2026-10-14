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


def test_check_dry_run_with_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    base = ["check", str(EXAMPLE), "--agent", "bot", "--server", "demo", "--tool", "sleep"]
    assert main([*base, "--arguments", '{"seconds": 1}']) == 0
    assert "allow: bot -> demo/sleep (rule demo-basics" in capsys.readouterr().out
    assert main([*base, "--arguments", '{"seconds": 30}']) == 0
    assert "deny: bot -> demo/sleep (rule short-sleeps-only" in capsys.readouterr().out


@pytest.mark.parametrize("raw", ["{nope", "[1, 2]"])
def test_check_rejects_bad_arguments(raw: str, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["check", str(EXAMPLE), "--agent", "a", "--server", "s", "--tool", "t"]
    assert main([*argv, "--arguments", raw]) == 2
    assert "--arguments" in capsys.readouterr().err
