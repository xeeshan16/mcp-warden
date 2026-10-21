"""Structured logging.

``WARDEN_LOG_FORMAT=json`` writes one JSON object per line for the gateway's
own logs and uvicorn's, ready for a log pipeline:

.. code-block:: json

    {"ts": "2026-10-21T09:12:03.418Z", "level": "info", "logger": "mcp_warden.app",
     "message": "approval apr_... approved by alice", "trace_id": "4bf9...", "span_id": "00f0..."}

Records logged inside a span carry its ``trace_id`` and ``span_id``, so a log
line can be joined to its trace. Fields passed with ``extra=`` are included;
uvicorn's access log is broken into ``client``, ``method``, ``path`` and
``status`` fields instead of a preformatted line.

``text`` (the default) keeps the plain format for reading in a terminal.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from opentelemetry import trace

# Attributes every LogRecord has; anything else came in through ``extra=``.
# ``color_message`` is uvicorn's copy of the message with terminal colour codes.
_STANDARD = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()
    | {"message", "asctime", "taskName", "color_message"}
)

TEXT_FORMAT = "%(levelname)s:     %(name)s: %(message)s"


class LogFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


class JsonFormatter(logging.Formatter):
    """One JSON object per record; never raises on odd ``extra`` values."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
        }
        if (
            record.name == "uvicorn.access"
            and isinstance(record.args, tuple)
            and len(record.args) == 5
        ):
            client, method, path, version, status = record.args
            payload["message"] = f"{method} {path} {status}"
            payload.update(
                client=_jsonable(client),
                method=_jsonable(method),
                path=_jsonable(path),
                http_version=_jsonable(version),
                status=_jsonable(status),
            )
        else:
            payload["message"] = record.getMessage()
        context = trace.get_current_span().get_span_context()
        if context.is_valid:
            payload["trace_id"] = format(context.trace_id, "032x")
            payload["span_id"] = format(context.span_id, "016x")
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_") and key not in payload:
                payload[key] = _jsonable(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def logging_config(level: str, fmt: LogFormat) -> dict[str, Any]:
    """A :func:`logging.config.dictConfig` for the gateway and uvicorn."""
    level = level.upper()
    if fmt is LogFormat.JSON:
        formatters: dict[str, Any] = {
            "default": {"()": JsonFormatter},
            "access": {"()": JsonFormatter},
        }
    else:
        formatters = {
            "default": {"()": "uvicorn.logging.DefaultFormatter", "fmt": TEXT_FORMAT},
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        }
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "class": "logging.StreamHandler",
                "formatter": "access",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": level, "propagate": False},
            "uvicorn.error": {"level": level},
            "uvicorn.access": {"handlers": ["access"], "level": level, "propagate": False},
            # Without this the gateway's info lines (admin changes, policy
            # reloads) would be dropped: uvicorn configures only its own loggers.
            "mcp_warden": {"handlers": ["default"], "level": level, "propagate": False},
        },
    }
