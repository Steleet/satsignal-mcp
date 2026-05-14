"""Deterministic JSON canonicalization for anchor_json.

We use stdlib `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` — not full RFC-8785 JCS (which has additional
rules for unicode normalization and IEEE-754 number serialization),
but deterministic for the JSON shapes an LLM tool call will produce
(dict / list / str / int / bool / None, and floats restricted to
finite values).

The canonical bytes are returned to the caller so they can save the
same bytes alongside the receipt — the sha256_hex on-chain is only
verifiable against bytes the caller can reproduce.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _check_finite(obj: Any, path: str = "") -> None:
    """Reject NaN / Infinity — they can be serialized by Python's json
    module with `allow_nan=True` but are not valid JSON per RFC 8259.
    A non-reproducible canonicalization defeats the entire point."""
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise CanonicalizationError(
                f"non-finite float at {path or '<root>'}: {obj!r}",
            )
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"non-string key at {path or '<root>'}: {k!r} "
                    f"({type(k).__name__})",
                )
            _check_finite(v, f"{path}.{k}" if path else k)
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_finite(v, f"{path}[{i}]")
        return


def canonicalize(data: Any) -> bytes:
    """Return the canonical JSON bytes for `data`. UTF-8 encoded."""
    _check_finite(data)
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
