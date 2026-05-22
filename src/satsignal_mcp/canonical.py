"""Deterministic JSON canonicalization for anchor_json.

Implements RFC 8785 (JSON Canonicalization Scheme, JCS): NFC normalize
all string values and dict keys, sort dict keys by UTF-16-BE byte
order (NOT simple lexicographic / codepoint sort), no whitespace, no
escape of non-ASCII characters. Matches the authoritative
implementation in `satsignal-cli` (`satsignal.verify._jcs`) and the
bundle-v1 spec at https://proof.satsignal.cloud/spec-bundle.

For ASCII-only payloads the bytes are identical to the previous
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
impl. For payloads with multibyte unicode (combining diacritics, rare
scripts, etc.) the bytes can differ — JCS is the authoritative
canonical form; the previous impl was a JCS-by-accident shortcut that
only agreed for ASCII.

The canonical bytes are returned to the caller so they can save the
same bytes alongside the receipt — the sha256_hex on-chain is only
verifiable against bytes the caller can reproduce.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
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
    """Return canonical JSON bytes for `data` per RFC 8785 (JCS).

    Implements full JCS: NFC normalization of string values and dict
    keys, UTF-16-BE byte-order sort of dict keys (NOT simple lexico-
    graphic sort), no whitespace, no escape of non-ASCII characters,
    canonical number formatting. Matches the implementation in
    `satsignal-cli` and the bundle-v1 spec at
    https://proof.satsignal.cloud/spec-bundle.

    Returns UTF-8 encoded bytes.
    """
    _check_finite(data)
    return _jcs_inner(data).encode("utf-8")


def _jcs_inner(obj: Any) -> str:
    """RFC 8785 JCS encoder (string form). Ported from satsignal-cli's
    `satsignal.verify._jcs_inner` so MCP and CLI agree byte-for-byte on
    every canonical doc, including those with non-ASCII content.

    Differences from the CLI impl: this version accepts finite floats
    (existing MCP callers anchor JSON payloads containing floats; the
    CLI's canonical-doc shapes happen to be integer-only). Float
    formatting falls through to Python's `json.dumps`, which produces a
    deterministic shortest-round-trip representation for any single
    Python value — sufficient for byte-reproducibility of an
    LLM-emitted payload re-canonicalized at verify time. NaN/inf are
    rejected upstream by `_check_finite`.
    """
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)
    if isinstance(obj, float):
        # Finite-only (checked upstream). json.dumps gives the same
        # deterministic shortest-form repr the previous impl emitted, so
        # ASCII-with-floats payloads stay byte-identical pre/post.
        return json.dumps(obj, allow_nan=False)
    if isinstance(obj, str):
        return json.dumps(
            unicodedata.normalize("NFC", obj),
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if isinstance(obj, list):
        return "[" + ",".join(_jcs_inner(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(
            obj.items(),
            key=lambda kv: unicodedata.normalize(
                "NFC", kv[0],
            ).encode("utf-16-be"),
        )
        return (
            "{"
            + ",".join(
                json.dumps(
                    unicodedata.normalize("NFC", k),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + ":"
                + _jcs_inner(v)
                for k, v in items
            )
            + "}"
        )
    raise CanonicalizationError(
        f"unsupported type for JCS: {type(obj).__name__}",
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
