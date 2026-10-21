"""Structured JSON logs."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap

from opentelemetry.sdk.trace import TracerProvider

from mcp_warden.observability.logs import JsonFormatter, LogFormat, logging_config


def record(name: str = "mcp_warden.app", msg: str = "hello %s", *args: object) -> logging.LogRecord:
    return logging.LogRecord(name, logging.INFO, __file__, 1, msg, args or ("world",), None)


def test_json_lines_carry_level_logger_message_and_extras() -> None:
    rec = record()
    rec.reviewer = "alice"
    rec.changes = {"rules": ("a", "b")}
    rec.odd = object()
    rec.color_message = "hello \x1b[36mworld\x1b[0m"
    line = json.loads(JsonFormatter().format(rec))
    assert line["level"] == "info"
    assert line["logger"] == "mcp_warden.app"
    assert line["message"] == "hello world"
    assert line["ts"].endswith("Z")
    assert line["reviewer"] == "alice"
    assert line["changes"] == {"rules": ["a", "b"]}
    assert line["odd"].startswith("<object object")
    assert "trace_id" not in line
    # Standard LogRecord attributes are not repeated as fields.
    assert not {"args", "msg", "levelno", "pathname", "color_message"} & line.keys()


def test_exceptions_are_included() -> None:
    try:
        raise ValueError("bad")
    except ValueError:
        rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    line = json.loads(JsonFormatter().format(rec))
    assert "ValueError: bad" in line["exception"]


def test_lines_logged_inside_a_span_carry_its_ids() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("work") as span:
        line = json.loads(JsonFormatter().format(record()))
        ctx = span.get_span_context()
    assert line["trace_id"] == format(ctx.trace_id, "032x")
    assert line["span_id"] == format(ctx.span_id, "016x")


def test_uvicorn_access_lines_become_fields() -> None:
    rec = record(
        "uvicorn.access",
        '%s - "%s %s HTTP/%s" %d',
        "127.0.0.1:5000",
        "POST",
        "/mcp/demo",
        "1.1",
        200,
    )
    line = json.loads(JsonFormatter().format(rec))
    assert line["message"] == "POST /mcp/demo 200"
    assert (line["method"], line["path"], line["status"]) == ("POST", "/mcp/demo", 200)
    assert line["client"] == "127.0.0.1:5000"


def test_both_formats_build_a_valid_configuration() -> None:
    for fmt in LogFormat:
        config = logging_config("debug", fmt)
        assert config["loggers"]["mcp_warden"]["level"] == "DEBUG"
        assert config["loggers"]["uvicorn.access"]["handlers"] == ["access"]


def test_json_configuration_end_to_end_in_a_fresh_interpreter() -> None:
    # Run in a subprocess: dictConfig changes process-wide logging state.
    script = textwrap.dedent(
        """
        import logging, logging.config
        from mcp_warden.observability.logs import LogFormat, logging_config
        logging.config.dictConfig(logging_config("info", LogFormat.JSON))
        logging.getLogger("mcp_warden.app").info("reloaded %s", "policy", extra={"rules": 3})
        logging.getLogger("mcp_warden.app").debug("hidden")
        logging.getLogger("uvicorn.error").warning("started")
        """
    )
    done = subprocess.run(  # noqa: S603 - fixed script, current interpreter
        [sys.executable, "-c", script], capture_output=True, text=True, check=True, timeout=60
    )
    lines = [json.loads(line) for line in done.stderr.splitlines()]
    assert [(entry["logger"], entry["message"]) for entry in lines] == [
        ("mcp_warden.app", "reloaded policy"),
        ("uvicorn.error", "started"),
    ]
    assert lines[0]["rules"] == 3
