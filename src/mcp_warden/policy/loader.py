"""Loading policies from YAML with readable error messages."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_warden.policy.model import Policy

MAX_POLICY_BYTES = 1_000_000


class PolicyError(ValueError):
    """Raised when a policy document cannot be parsed or validated."""


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        location = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"{location}: {err['msg']}")
    return "; ".join(lines)


def parse_policy(data: Any) -> Policy:
    """Validate an already-decoded policy mapping."""
    if not isinstance(data, dict):
        raise PolicyError("policy document must be a mapping at the top level")
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"invalid policy: {_format_validation_error(exc)}") from exc


def load_policy(text: str) -> Policy:
    """Parse and validate a YAML policy document."""
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy document exceeds {MAX_POLICY_BYTES} bytes")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc
    return parse_policy(data)


def load_policy_file(path: str | Path) -> Policy:
    """Read, parse and validate a YAML policy file."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {file_path}: {exc.strerror}") from exc
    return load_policy(text)
