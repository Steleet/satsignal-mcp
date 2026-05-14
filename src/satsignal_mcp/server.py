"""Satsignal MCP server — exposes anchoring + lookup as agent-callable tools.

Runs on stdio. Configured via env:
  SATSIGNAL_API_KEY    Bearer token (required for anchoring; unused by
                       lookup_hash / verify_bundle which are read-only).
  SATSIGNAL_API_BASE   Default https://proof.satsignal.cloud.
  SATSIGNAL_MATTER     Default matter_slug ("inbox" if unset).

Tools (v0.1):
  anchor_file          sha256 a local file, POST to /api/v1/anchors.
  anchor_text          sha256 a UTF-8 string.
  anchor_json          Canonicalize JSON (sort_keys), sha256, anchor.
  lookup_hash          Read-only check whether a sha is on-chain.
  verify_bundle        Open a local .mbnt, extract sha + txid, chain-
                       confirm via lookup_hash.

Dry-run policy: every anchor tool accepts `dry_run: bool = false`. When
true the tool computes the sha + canonical bytes and returns a preview
without touching the network. The Satsignal API does NOT itself honor
dry_run — see customer/routes.py reserved-field hint. dry_run lives in
the MCP layer.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import mcp.types as mtypes
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .api import ApiError, SatsignalApi
from .canonical import CanonicalizationError, canonicalize, sha256_hex


_SERVER_NAME = "satsignal"

_INSTRUCTIONS = (
    "Satsignal anchors a sha256 of your input to the BSV blockchain, "
    "returning a receipt that proves the input existed in that exact "
    "form at a specific time. Use anchor_file / anchor_text / "
    "anchor_json to create a receipt; lookup_hash / verify_bundle to "
    "check one. Each anchor call broadcasts a real on-chain transaction "
    "and counts against the workspace's daily quota — pass dry_run=true "
    "first if you want to preview the sha256 before committing."
)


def _env_api_base() -> str:
    return (os.environ.get("SATSIGNAL_API_BASE")
            or "https://proof.satsignal.cloud").rstrip("/")


def _env_api_key() -> str | None:
    v = os.environ.get("SATSIGNAL_API_KEY", "").strip()
    return v or None


def _env_default_matter() -> str:
    return (os.environ.get("SATSIGNAL_MATTER") or "inbox").strip() or "inbox"


# ─────────────────────────── tool list ────────────────────────────────

def _tool_definitions() -> list[mtypes.Tool]:
    matter_field = {
        "type": "string",
        "description": (
            "Matter slug within the workspace. Defaults to the "
            "SATSIGNAL_MATTER env var or 'inbox'."
        ),
    }
    label_field = {
        "type": "string",
        "description": (
            "Optional short label shown on the receipt. "
            "Attacker-controllable; treat as untrusted display text."
        ),
    }
    dry_run_field = {
        "type": "boolean",
        "default": False,
        "description": (
            "If true, compute the sha256 and report what WOULD be "
            "anchored without touching the network or burning quota."
        ),
    }
    force_new_field = {
        "type": "boolean",
        "default": False,
        "description": (
            "By default the API dedups: re-anchoring the same "
            "sha256_hex in the same matter returns the prior receipt "
            "without broadcasting. force_new=true opts out — useful "
            "for refreshing the chain timestamp."
        ),
    }
    return [
        mtypes.Tool(
            name="anchor_file",
            description=(
                "Anchor a local file: compute its sha256, POST to "
                "Satsignal, return the receipt. The file's bytes never "
                "leave this machine; only the hash is sent."
            ),
            inputSchema={
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the file.",
                    },
                    "matter": matter_field,
                    "label": label_field,
                    "dry_run": dry_run_field,
                    "force_new": force_new_field,
                },
            },
        ),
        mtypes.Tool(
            name="anchor_text",
            description=(
                "Anchor a UTF-8 text payload. Computes "
                "sha256(text.encode('utf-8')) and anchors the digest."
            ),
            inputSchema={
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to anchor.",
                    },
                    "matter": matter_field,
                    "label": label_field,
                    "dry_run": dry_run_field,
                    "force_new": force_new_field,
                },
            },
        ),
        mtypes.Tool(
            name="anchor_json",
            description=(
                "Canonicalize a JSON object (sorted keys, compact "
                "separators, UTF-8), sha256 the bytes, and anchor. The "
                "canonical bytes are returned in the response so the "
                "caller can save them alongside the receipt — "
                "verification later requires reproducing the same bytes."
            ),
            inputSchema={
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": {
                        "description": (
                            "Any JSON value (object, array, string, "
                            "number, bool, null). NaN / Infinity / "
                            "non-string keys are rejected."
                        ),
                    },
                    "matter": matter_field,
                    "label": label_field,
                    "dry_run": dry_run_field,
                    "force_new": force_new_field,
                },
            },
        ),
        mtypes.Tool(
            name="lookup_hash",
            description=(
                "Check whether a sha256 is anchored on-chain. Read-only, "
                "no auth required. Returns {hit, bundle_id, txid, "
                "created_utc} on hit, {hit:false, reason} on miss."
            ),
            inputSchema={
                "type": "object",
                "required": ["sha256_hex"],
                "properties": {
                    "sha256_hex": {
                        "type": "string",
                        "description": "64-char lowercase hex sha256.",
                    },
                },
            },
        ),
        mtypes.Tool(
            name="verify_bundle",
            description=(
                "Open a local .mbnt receipt bundle, extract its "
                "sha256_hex + txid, and chain-confirm via /lookup_hash. "
                "Returns verified=true only when the bundle's claimed "
                "txid matches what the index reports for that sha. "
                "This is a fast chain-confirm only; full cryptographic "
                "validation is in satsignal-cli."
            ),
            inputSchema={
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the .mbnt bundle.",
                    },
                },
            },
        ),
    ]


# ─────────────────────────── tool handlers ────────────────────────────

def _text_response(payload: Any) -> list[mtypes.TextContent]:
    return [mtypes.TextContent(
        type="text",
        text=json.dumps(payload, indent=2, sort_keys=True),
    )]


def _error_response(message: str, *, code: str = "error",
                    **extras: Any) -> list[mtypes.TextContent]:
    return _text_response({"error": code, "message": message, **extras})


def _anchor_result_payload(*, sha: str, matter: str, label: str | None,
                            file_size: int | None,
                            anchor) -> dict:
    return {
        "anchored": True,
        "sha256_hex": sha,
        "bundle_id": anchor.bundle_id,
        "txid": anchor.txid,
        "mode": anchor.mode,
        "matter_slug": anchor.matter_slug,
        "receipt_url": anchor.receipt_url,
        "bundle_url": anchor.bundle_url,
        "duplicate": anchor.duplicate,
        **({"label": label} if label else {}),
        **({"file_size": file_size} if file_size is not None else {}),
    }


def _hash_file(path: Path, *, chunk_size: int = 1 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


async def _handle_anchor_file(args: dict, api: SatsignalApi
                              ) -> list[mtypes.TextContent]:
    raw_path = args.get("path") or ""
    if not isinstance(raw_path, str) or not raw_path:
        return _error_response("path is required", code="missing_path")
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return _error_response(f"not a file: {path}", code="not_a_file")

    sha, size = _hash_file(path)
    matter = (args.get("matter") or _env_default_matter()).strip() or "inbox"
    label = args.get("label") or None
    dry_run = bool(args.get("dry_run", False))
    force_new = bool(args.get("force_new", False))

    if dry_run:
        return _text_response({
            "anchored": False,
            "dry_run": True,
            "sha256_hex": sha,
            "file_size": size,
            "filename": path.name,
            "matter_slug": matter,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. Pass dry_run=false (or omit) to broadcast."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            matter_slug=matter,
            sha256_hex=sha,
            file_size=size,
            label=label,
            filename=path.name,
            force_new=force_new,
        )
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    return _text_response(_anchor_result_payload(
        sha=sha, matter=matter, label=label, file_size=size, anchor=anchor,
    ))


async def _handle_anchor_text(args: dict, api: SatsignalApi
                              ) -> list[mtypes.TextContent]:
    text = args.get("text")
    if not isinstance(text, str):
        return _error_response("text is required (string)", code="missing_text")
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    size = len(raw)
    matter = (args.get("matter") or _env_default_matter()).strip() or "inbox"
    label = args.get("label") or None
    dry_run = bool(args.get("dry_run", False))
    force_new = bool(args.get("force_new", False))

    if dry_run:
        return _text_response({
            "anchored": False,
            "dry_run": True,
            "sha256_hex": sha,
            "byte_length": size,
            "matter_slug": matter,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. The sha256 covers exactly "
                "text.encode('utf-8'). Pass dry_run=false to broadcast."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            matter_slug=matter,
            sha256_hex=sha,
            file_size=size,
            label=label,
            force_new=force_new,
        )
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    return _text_response(_anchor_result_payload(
        sha=sha, matter=matter, label=label, file_size=size, anchor=anchor,
    ))


async def _handle_anchor_json(args: dict, api: SatsignalApi
                              ) -> list[mtypes.TextContent]:
    if "data" not in args:
        return _error_response("data is required", code="missing_data")
    try:
        canonical = canonicalize(args["data"])
    except CanonicalizationError as e:
        return _error_response(str(e), code="canonicalization_failed")
    sha = sha256_hex(canonical)
    size = len(canonical)
    matter = (args.get("matter") or _env_default_matter()).strip() or "inbox"
    label = args.get("label") or None
    dry_run = bool(args.get("dry_run", False))
    force_new = bool(args.get("force_new", False))

    canonical_str = canonical.decode("utf-8")
    if dry_run:
        return _text_response({
            "anchored": False,
            "dry_run": True,
            "sha256_hex": sha,
            "byte_length": size,
            "canonical_bytes": canonical_str,
            "matter_slug": matter,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. Save the canonical_bytes alongside the "
                "future receipt — verification requires reproducing "
                "these exact bytes."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            matter_slug=matter,
            sha256_hex=sha,
            file_size=size,
            label=label,
            force_new=force_new,
        )
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    payload = _anchor_result_payload(
        sha=sha, matter=matter, label=label, file_size=size, anchor=anchor,
    )
    payload["canonical_bytes"] = canonical_str
    return _text_response(payload)


async def _handle_lookup_hash(args: dict, api: SatsignalApi
                              ) -> list[mtypes.TextContent]:
    sha = args.get("sha256_hex")
    if not isinstance(sha, str):
        return _error_response("sha256_hex is required (string)",
                               code="missing_sha")
    try:
        result = await api.lookup_hash(sha)
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    if result.get("miss"):
        return _text_response({
            "hit": False,
            "reason": result.get("reason"),
            "sha256_hex": sha.lower().strip(),
        })
    return _text_response({
        "hit": True,
        "sha256_hex": sha.lower().strip(),
        "bundle_id": result.get("bundle_id"),
        "txid": result.get("txid"),
        "created_utc": result.get("created_utc"),
    })


def _extract_bundle_claims(bundle_path: Path) -> tuple[dict, dict]:
    """Open a .mbnt zip, return (manifest, canonical) as dicts."""
    with zipfile.ZipFile(bundle_path) as zf:
        names = set(zf.namelist())
        if "manifest.json" not in names:
            raise ValueError("manifest.json missing from bundle")
        if "canonical.json" not in names:
            raise ValueError("canonical.json missing from bundle")
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        canonical = json.loads(zf.read("canonical.json").decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json is not a JSON object")
    if not isinstance(canonical, dict):
        raise ValueError("canonical.json is not a JSON object")
    return manifest, canonical


async def _handle_verify_bundle(args: dict, api: SatsignalApi
                                ) -> list[mtypes.TextContent]:
    raw_path = args.get("path") or ""
    if not isinstance(raw_path, str) or not raw_path:
        return _error_response("path is required", code="missing_path")
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return _error_response(f"not a file: {path}", code="not_a_file")
    if not zipfile.is_zipfile(path):
        return _error_response(f"{path} is not a .mbnt (ZIP) bundle",
                               code="not_a_bundle")

    try:
        manifest, canonical = _extract_bundle_claims(path)
    except (ValueError, zipfile.BadZipFile, KeyError) as e:
        return _error_response(f"could not read bundle: {e}",
                               code="bad_bundle")

    # The 64-hex file sha lives in canonical.subject.document_sha256;
    # /lookup_hash indexes that field. manifest.doc_hash_expected is
    # a 40-hex truncated hash of the canonical doc embedded on-chain
    # (the OP_RETURN payload), NOT the file hash — not lookup-able.
    subject = canonical.get("subject") or {}
    claimed_sha = subject.get("document_sha256")
    if not isinstance(claimed_sha, str) or len(claimed_sha) != 64:
        return _error_response(
            "bundle has no document_sha256 in canonical.subject (sealed "
            "or manifest-mode bundles don't expose a naked file sha; "
            "chain-confirm via lookup_hash isn't applicable).",
            code="no_file_sha",
            manifest_mode=manifest.get("mode"),
        )
    claimed_txid = manifest.get("txid")

    try:
        result = await api.lookup_hash(claimed_sha)
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)

    if result.get("miss"):
        return _text_response({
            "verified": False,
            "reason": "sha_not_indexed",
            "claimed_sha256_hex": claimed_sha,
            "claimed_txid": claimed_txid,
            "lookup_reason": result.get("reason"),
        })

    indexed_txid = result.get("txid")
    txid_matches = bool(
        claimed_txid and indexed_txid and claimed_txid == indexed_txid,
    )
    return _text_response({
        "verified": txid_matches,
        "claimed_sha256_hex": claimed_sha,
        "claimed_txid": claimed_txid,
        "indexed_txid": indexed_txid,
        "bundle_id": result.get("bundle_id"),
        "created_utc": result.get("created_utc"),
        **({"reason": "txid_mismatch"} if claimed_txid and not txid_matches
           else {}),
        **({"reason": "no_txid_in_bundle"} if not claimed_txid else {}),
    })


_HANDLERS = {
    "anchor_file": _handle_anchor_file,
    "anchor_text": _handle_anchor_text,
    "anchor_json": _handle_anchor_json,
    "lookup_hash": _handle_lookup_hash,
    "verify_bundle": _handle_verify_bundle,
}


# ─────────────────────────── server wiring ────────────────────────────

def build_server() -> Server:
    server = Server(_SERVER_NAME, version=__version__,
                    instructions=_INSTRUCTIONS)

    @server.list_tools()
    async def list_tools() -> list[mtypes.Tool]:
        return _tool_definitions()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None
                        ) -> list[mtypes.TextContent]:
        handler = _HANDLERS.get(name)
        if handler is None:
            return _error_response(
                f"unknown tool: {name!r}", code="unknown_tool",
            )
        api = SatsignalApi(api_base=_env_api_base(),
                           api_key=_env_api_key())
        try:
            return await handler(arguments or {}, api)
        finally:
            await api.aclose()

    return server


async def _run() -> None:
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
