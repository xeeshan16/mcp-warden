"""Token estimation for budgets.

Budgets count tokens without knowing which model sits behind the agent, so
the count is an estimate behind a small interface. The default estimator is a
deterministic character ratio: no model files, no network, identical results
on every host, which is what quotas and tests need. A tokenizer-backed
estimator can be plugged in through :class:`TokenEstimator` when exact counts
for one model family matter more than portability.

What is counted is the canonical JSON of the call (tool name and arguments)
and of the upstream's reply (``result`` or ``error``), so whitespace and key
order chosen by the client or server never change the count.
"""

from __future__ import annotations

import json
import math
from typing import Any, Protocol


class TokenEstimator(Protocol):
    def count(self, text: str) -> int:
        """Estimated tokens in ``text``; never negative, ``0`` for an empty string."""
        ...


class CharRatioEstimator:
    """``ceil(characters / chars_per_token)``.

    Four characters per token is the usual rule of thumb for English text and
    JSON with BPE tokenizers. It is an estimate, and documented as one.
    """

    def __init__(self, chars_per_token: float = 4.0) -> None:
        if not math.isfinite(chars_per_token) or chars_per_token <= 0:
            raise ValueError("chars_per_token must be a positive number")
        self.chars_per_token = chars_per_token

    def count(self, text: str) -> int:
        return math.ceil(len(text) / self.chars_per_token)

    def __repr__(self) -> str:
        return f"CharRatioEstimator(chars_per_token={self.chars_per_token})"


def canonical_json(value: Any) -> str:
    """Compact JSON with sorted keys, so equal values always count the same."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
