from __future__ import annotations

from pathlib import Path

import pytest

from mcp_warden.__main__ import main
from mcp_warden.db.migrate import head_revision

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


def test_identity_commands_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = ["--database-url", f"sqlite:///{tmp_path / 'cli.db'}"]
    assert main(["agents", "list", *url]) == 1
    assert "mcp-warden db upgrade" in capsys.readouterr().err

    assert main(["db", "upgrade", *url]) == 0
    assert f"database at revision {head_revision()}" in capsys.readouterr().out

    assert main(["agents", "create", "support-bot", "--description", "tickets", *url]) == 0
    assert main(["agents", "create", "support-bot", *url]) == 1
    assert "already exists" in capsys.readouterr().err

    assert (
        main(["keys", "issue", "support-bot", "--label", "ci", "--expires-in-days", "30", *url])
        == 0
    )
    captured = capsys.readouterr()
    key = captured.out.strip()
    assert key.startswith("mcpw_")
    prefix = key.split("_")[1]
    assert f"issued key {prefix}" in captured.err
    assert "shown only once" in captured.err

    assert main(["keys", "list", "support-bot", *url]) == 0
    listing = capsys.readouterr().out
    assert prefix in listing
    assert "active" in listing
    assert key not in listing

    assert main(["keys", "revoke", prefix, *url]) == 0
    assert f"revoked key {prefix} of support-bot" in capsys.readouterr().out
    assert main(["keys", "list", "support-bot", *url]) == 0
    assert "revoked" in capsys.readouterr().out

    assert main(["agents", "disable", "support-bot", *url]) == 0
    assert main(["agents", "list", *url]) == 0
    assert "support-bot\tdisabled" in capsys.readouterr().out
    assert main(["agents", "enable", "support-bot", *url]) == 0

    assert main(["keys", "issue", "ghost", *url]) == 1
    assert "no such agent" in capsys.readouterr().err


def test_expiry_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["keys", "issue", "bot", "--expires-in-days", "0"])


def test_serve_shows_the_gateways_own_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    import logging.config

    import uvicorn

    ran: list[dict[str, object]] = []
    configured: list[dict[str, object]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: ran.append(kwargs))
    # Recorded rather than applied, so the test leaves global logging alone.
    monkeypatch.setattr(logging.config, "dictConfig", configured.append)
    monkeypatch.setenv("WARDEN_AUTH_MODE", "trusted-header")
    monkeypatch.setenv("WARDEN_LOG_LEVEL", "info")
    assert main(["serve", "--policy", str(EXAMPLE)]) == 0
    assert len(ran) == 1
    kwargs = ran[0]
    assert (kwargs["host"], kwargs["port"], kwargs["log_level"]) == ("127.0.0.1", 8080, "info")
    # Uvicorn gets the same configuration that was applied before it started,
    # and it routes the gateway's own logger, not only uvicorn's.
    assert configured == [kwargs["log_config"]]
    loggers = configured[0]["loggers"]
    assert isinstance(loggers, dict)
    assert loggers["mcp_warden"]["level"] == "INFO"
