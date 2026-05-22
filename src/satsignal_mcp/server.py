"""Satsignal MCP server — exposes anchoring + lookup as agent-callable tools.

Runs on stdio. Configured via env:
  SATSIGNAL_API_KEY    Bearer token (required for anchoring; unused by
                       lookup_hash / chain_confirm_bundle /
                       verify_file_against_bundle which are read-only).
  SATSIGNAL_API_BASE   Default https://app.satsignal.cloud (customer
                       API host — see api.DEFAULT_API_BASE).
  SATSIGNAL_FOLDER     Default folder ("inbox" if unset).
  SATSIGNAL_MATTER     Legacy alias of SATSIGNAL_FOLDER (still honored,
                       byte-identical, never removed; SATSIGNAL_FOLDER
                       takes precedence if both are set).

Vocabulary note: the public input name is `folder` (env
SATSIGNAL_FOLDER). `matter` / SATSIGNAL_MATTER are the frozen legacy
aliases — still accepted with byte-identical behavior and never
removed. On the wire to the Satsignal API the body key stays the
frozen legacy `matter_slug` (accepted by every Satsignal server, incl.
older / self-hosted); `folder` is folded into `matter_slug` before the
network call. If both `folder` and `matter` are sent with non-empty
values that DIFFER, the tool returns a validation error rather than
silently picking one.

Tools (v0.4):
  anchor_file                  sha256 a local file, POST to /api/v1/anchors.
  anchor_text                  sha256 a UTF-8 string.
  anchor_json                  Canonicalize JSON (sort_keys), sha256, anchor.
  lookup_hash                  Read-only check whether a sha is on-chain.
  chain_confirm_bundle         Open a local .mbnt, extract sha + txid,
                               chain-confirm via lookup_hash. Fast, but
                               does NOT detect file tampering — the
                               original file is never opened.
  verify_file_against_bundle   Full verify: re-hash the original file,
                               compare to the bundle's claimed sha,
                               and chain-confirm via public block
                               explorers. Detects tampering.
  verify_bundle                Deprecated + FAIL-CLOSED (v0.4): every
                               call returns a structured error
                               (deprecated_tool_blocked) directing the
                               caller to verify_file_against_bundle or
                               chain_confirm_bundle. Removable in 0.5.

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
    "returning a receipt that proves the anchorer held this exact "
    "input by a specific time (tamper-evidence and timing — not "
    "authorship, and not that the input existed before the anchor). "
    "Use anchor_file / anchor_text / anchor_json to create a receipt. "
    "To check a receipt, use verify_file_against_bundle when you have "
    "the original file in hand (full verify: detects tampering) — or "
    "chain_confirm_bundle for a fast chain-only check when the file "
    "isn't available. lookup_hash is a raw sha → txid index lookup. "
    "Each anchor call broadcasts a real on-chain transaction and "
    "counts against the workspace's daily quota — pass dry_run=true "
    "first if you want to preview the sha256 before committing."
)


def _env_api_base() -> str:
    # Default mirrors api.DEFAULT_API_BASE (app.satsignal.cloud, the
    # customer API host). Earlier proof.satsignal.cloud default was a
    # bug — see api.py for the host-role split.
    from .api import DEFAULT_API_BASE
    return (os.environ.get("SATSIGNAL_API_BASE")
            or DEFAULT_API_BASE).rstrip("/")


def _env_api_key() -> str | None:
    v = os.environ.get("SATSIGNAL_API_KEY", "").strip()
    return v or None


def _env_default_folder() -> str:
    """Default folder slug.

    SATSIGNAL_FOLDER is the public env var; SATSIGNAL_MATTER is the
    frozen legacy alias. SATSIGNAL_FOLDER wins when both are set;
    SATSIGNAL_MATTER alone still works byte-identically to the
    pre-alias behavior.
    """
    val = os.environ.get("SATSIGNAL_FOLDER")
    if val is None or not val.strip():
        val = os.environ.get("SATSIGNAL_MATTER")
    return (val or "inbox").strip() or "inbox"


# Kept as the frozen legacy name so any external import still resolves.
# Identical resolution to _env_default_folder (SATSIGNAL_FOLDER wins,
# SATSIGNAL_MATTER fallback) — i.e. legacy SATSIGNAL_MATTER-only setups
# are byte-identical to pre-alias behavior.
_env_default_matter = _env_default_folder


class FolderAliasConflict(ValueError):
    """Both `folder` and `matter` supplied with differing non-empty
    values. Aliases must not disagree — caller must send only one
    (or send equal values)."""


def _resolve_folder(args: dict) -> str:
    """Resolve the effective folder slug from a tool's arguments.

    `folder` is the public name; `matter` is the frozen legacy alias.
    Conflict rule (mirrors the Satsignal server):
      - both present, non-empty, and DIFFERENT  -> FolderAliasConflict
      - both present and equal                   -> accept that value
      - exactly one present (non-empty)          -> use it
      - neither present                          -> env default
        (SATSIGNAL_FOLDER, then legacy SATSIGNAL_MATTER, then 'inbox')

    Precedence when reconciling: `folder` is preferred over `matter`.
    Whitespace-only values are treated as absent (matches the prior
    `args.get("matter") or default` behavior).
    """
    raw_folder = args.get("folder")
    raw_matter = args.get("matter")

    folder = raw_folder.strip() if isinstance(raw_folder, str) else ""
    matter = raw_matter.strip() if isinstance(raw_matter, str) else ""

    if folder and matter and folder != matter:
        raise FolderAliasConflict(
            "folder and matter are aliases and must not be sent with "
            "different values; send only folder "
            f"(got folder={folder!r}, matter={matter!r})."
        )
    # `folder` preferred; fall back to legacy `matter`; else env default.
    chosen = folder or matter
    return chosen or _env_default_folder()


# ─────────────────────────── tool list ────────────────────────────────

def _tool_definitions() -> list[mtypes.Tool]:
    folder_field = {
        "type": "string",
        "description": (
            "Folder slug within the workspace. Defaults to the "
            "SATSIGNAL_FOLDER env var (legacy SATSIGNAL_MATTER still "
            "honored) or 'inbox'. Sent to the API as the frozen "
            "`matter_slug` wire field for backward compatibility."
        ),
    }
    matter_field = {
        "type": "string",
        "description": (
            "Legacy alias of `folder` (frozen; still accepted, never "
            "removed). Prefer `folder`. Sending both `folder` and "
            "`matter` with different non-empty values is an error; "
            "equal values are accepted."
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
            "sha256_hex in the same folder returns the prior receipt "
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
                    "folder": folder_field,
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
                    "folder": folder_field,
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
                    "folder": folder_field,
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
            name="chain_confirm_bundle",
            description=(
                "CHAIN-CONFIRM ONLY: open a local .mbnt bundle, extract "
                "its claimed sha + txid, and confirm via /lookup_hash "
                "that the sha was anchored at that txid. Does NOT open "
                "the original file, so a tampered original is NOT "
                "detected — the bundle stays self-consistent. For full "
                "verify (including tamper detection), use "
                "verify_file_against_bundle. Pass `bundle_path` (the "
                "new canonical name) OR `path` (the legacy alias from "
                "verify_bundle); the handler accepts either."
            ),
            # Note: bundle_path is NOT in `required` so we can honor the
            # legacy `path` arg too. The handler enforces "exactly one
            # non-empty path argument" and returns conflicting_alias if
            # both are sent with differing values, or missing_bundle_path
            # if neither is sent.
            inputSchema={
                "type": "object",
                "properties": {
                    "bundle_path": {
                        "type": "string",
                        "description": (
                            "Path to the .mbnt bundle (NOT the original "
                            "file). Preferred over the legacy `path`."
                        ),
                    },
                    "path": {
                        "type": "string",
                        "description": (
                            "Legacy alias of bundle_path (from "
                            "verify_bundle in 0.2.x); still accepted."
                        ),
                    },
                },
            },
        ),
        mtypes.Tool(
            name="verify_file_against_bundle",
            description=(
                "FULL VERIFY: re-hash the original file, confirm it "
                "matches the bundle's claimed sha (crypto check, "
                "detects tampering), then chain-confirm via public "
                "block explorers (WoC + Bitails) that the on-chain "
                "doc_hash matches what the bundle says. Returns "
                "verified=true only when both checks pass. Use this "
                "when you have the original file in hand; "
                "chain_confirm_bundle is faster but can't detect a "
                "swapped original."
            ),
            inputSchema={
                "type": "object",
                "required": ["file_path", "bundle_path"],
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": (
                            "Path to the original file the bundle "
                            "claims to anchor. Will be sha256'd and "
                            "compared to the bundle's claimed hash."
                        ),
                    },
                    "bundle_path": {
                        "type": "string",
                        "description": "Path to the .mbnt bundle.",
                    },
                    "min_confirmations": {
                        "type": "integer",
                        "description": (
                            "Minimum block confirmations required to "
                            "return verified=true. Default 0 (any "
                            "inclusion counts; 0-conf means broadcast "
                            "but not yet mined)."
                        ),
                        "minimum": 0,
                    },
                },
            },
        ),
        mtypes.Tool(
            name="verify_bundle",
            description=(
                "DEPRECATED + FAIL-CLOSED — this name silently produced "
                "a chain-only confirmation under a name that implied "
                "full verify (the v0.2 false-PASS class). v0.4 blocks "
                "the alias: any call returns a structured error "
                "(deprecated_tool_blocked) directing you to "
                "verify_file_against_bundle (full verify, recommended) "
                "or chain_confirm_bundle (chain-only, accurate name). "
                "The tool is still listed so callers pinned by name "
                "get the redirect instead of unknown_tool. Removable "
                "in 0.5."
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

def _text_response(payload: Any) -> mtypes.CallToolResult:
    """Success response — wraps the JSON body in a `CallToolResult` with
    `isError=False` so MCP clients branching on `result.isError` (per
    protocol) correctly classify it. Text body shape is byte-identical
    to the pre-0.5 list[TextContent] return — naive clients reading
    `content[0].text` see no change."""
    return mtypes.CallToolResult(
        content=[mtypes.TextContent(
            type="text",
            text=json.dumps(payload, indent=2, sort_keys=True),
        )],
        isError=False,
    )


def _error_response(message: str, *, code: str = "error",
                    **extras: Any) -> mtypes.CallToolResult:
    """Error response — wraps the JSON body in a `CallToolResult` with
    `isError=True` so MCP clients branching on `result.isError` (per
    protocol) correctly distinguish error from success. Text body shape
    preserved: `{"error": <code>, "message": <human>, ...extras}`."""
    return mtypes.CallToolResult(
        content=[mtypes.TextContent(
            type="text",
            text=json.dumps(
                {"error": code, "message": message, **extras},
                indent=2,
                sort_keys=True,
            ),
        )],
        isError=True,
    )


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
                              ) -> mtypes.CallToolResult:
    raw_path = args.get("path") or ""
    if not isinstance(raw_path, str) or not raw_path:
        return _error_response("path is required", code="missing_path")
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return _error_response(f"not a file: {path}", code="not_a_file")

    sha, size = _hash_file(path)
    try:
        folder = _resolve_folder(args)
    except FolderAliasConflict as e:
        return _error_response(str(e), code="conflicting_alias")
    # `folder` is the resolved slug; it is sent to the API as the
    # frozen `matter_slug` wire field. Local name kept as `matter`
    # so downstream payload/api call are byte-identical to before.
    matter = folder
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
                              ) -> mtypes.CallToolResult:
    text = args.get("text")
    if not isinstance(text, str):
        return _error_response("text is required (string)", code="missing_text")
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    size = len(raw)
    try:
        folder = _resolve_folder(args)
    except FolderAliasConflict as e:
        return _error_response(str(e), code="conflicting_alias")
    matter = folder
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
                              ) -> mtypes.CallToolResult:
    if "data" not in args:
        return _error_response("data is required", code="missing_data")
    try:
        canonical = canonicalize(args["data"])
    except CanonicalizationError as e:
        return _error_response(str(e), code="canonicalization_failed")
    sha = sha256_hex(canonical)
    size = len(canonical)
    try:
        folder = _resolve_folder(args)
    except FolderAliasConflict as e:
        return _error_response(str(e), code="conflicting_alias")
    matter = folder
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
                              ) -> mtypes.CallToolResult:
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


async def _handle_chain_confirm_bundle(args: dict, api: SatsignalApi
                                       ) -> mtypes.CallToolResult:
    # Accept both `bundle_path` (new canonical name) and `path` (legacy
    # alias, still emitted by the deprecated verify_bundle tool). If
    # both are sent with different non-empty values, that's a caller
    # bug — refuse rather than silently picking one (matches the
    # folder/matter alias-conflict policy in _resolve_folder).
    raw_bundle = args.get("bundle_path")
    raw_path = args.get("path")
    bundle = raw_bundle.strip() if isinstance(raw_bundle, str) else ""
    legacy = raw_path.strip() if isinstance(raw_path, str) else ""
    if bundle and legacy and bundle != legacy:
        return _error_response(
            "bundle_path and path are aliases and must not be sent "
            "with different values; send only bundle_path.",
            code="conflicting_alias",
        )
    raw_path = bundle or legacy
    if not raw_path:
        return _error_response(
            "bundle_path is required", code="missing_bundle_path",
        )
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


# satsignal-cli's verify_file is the canonical full-verify entry point
# (crypto + doc_hash + public-explorer chain confirm in one call). Pinned
# as a runtime dependency so MCP installs get the whole verify story in
# one pip install. Import at module scope so a missing dep fails fast at
# startup, not on first tool invocation.
from satsignal.verify import VerifyClass, verify_file  # noqa: E402


# Pass-through map. PENDING is crypto+chain OK with 0 confirmations
# (broadcast but not yet mined) — still verified=true; the confirmations
# field surfaces the maturity. OFFLINE never appears because we never
# pass offline=True (would skip the chain check, violating the helper's
# chain-confirm-by-default contract).
_VERIFIED_CLASSES = frozenset({VerifyClass.VERIFIED, VerifyClass.PENDING})


async def _handle_verify_file_against_bundle(
    args: dict, api: SatsignalApi,  # api unused — kept for dispatch parity
) -> mtypes.CallToolResult:
    raw_file = args.get("file_path")
    raw_bundle = args.get("bundle_path")
    if not isinstance(raw_file, str) or not raw_file.strip():
        return _error_response(
            "file_path is required (the original file to re-hash)",
            code="missing_file_path",
        )
    if not isinstance(raw_bundle, str) or not raw_bundle.strip():
        return _error_response(
            "bundle_path is required (the .mbnt receipt bundle)",
            code="missing_bundle_path",
        )
    file_p = Path(raw_file).expanduser()
    bundle_p = Path(raw_bundle).expanduser()
    if not file_p.is_file():
        return _error_response(f"not a file: {file_p}", code="not_a_file",
                               which="file_path")
    if not bundle_p.is_file():
        return _error_response(f"not a file: {bundle_p}", code="not_a_file",
                               which="bundle_path")

    raw_min_conf = args.get("min_confirmations", 0)
    if not isinstance(raw_min_conf, int) or raw_min_conf < 0:
        return _error_response(
            "min_confirmations must be a non-negative integer",
            code="bad_min_confirmations",
        )

    # verify_file does its own bundle-format validation, so we don't
    # pre-check is_zipfile — let it bubble through as VerifyClass.CRYPTO
    # with a descriptive message.
    result = await asyncio.to_thread(
        verify_file, file_p, bundle_p,
        offline=False, min_confirmations=raw_min_conf,
    )

    verified = result.cls in _VERIFIED_CLASSES
    payload: dict[str, Any] = {
        "verified": verified,
        "verify_class": result.cls.value,
    }
    if result.sha256_hex:
        payload["file_sha256_hex"] = result.sha256_hex
    if result.txid:
        payload["txid"] = result.txid
    if result.confirmations is not None:
        payload["confirmations"] = result.confirmations
    if result.message:
        payload["reason"] = result.message
    return _text_response(payload)


async def _handle_verify_bundle_blocked(
    args: dict, api: SatsignalApi,  # both unused
) -> mtypes.CallToolResult:
    """Hard-block the deprecated verify_bundle alias.

    v0.3 deprecated this name but still routed it to chain_confirm_bundle,
    which silently produced `verified=true` on tampered originals — the
    v0.2 false-PASS class. v0.4 fail-closes the alias: every call returns
    a structured error directing the caller to the right v0.3 split tool.
    Removable in 0.5.
    """
    return _error_response(
        "verify_bundle is deprecated and intentionally fail-closed in 0.4. "
        "For full verification (detects file tampering), call "
        "verify_file_against_bundle(file_path, bundle_path). For the same "
        "chain-only semantics this alias used to provide, call "
        "chain_confirm_bundle(bundle_path) — accepts the legacy `path` "
        "alias. verify_bundle will be removed entirely in 0.5.",
        code="deprecated_tool_blocked",
        deprecated_tool="verify_bundle",
        full_verify_tool="verify_file_against_bundle",
        chain_only_tool="chain_confirm_bundle",
        removal_version="0.5",
    )


_HANDLERS = {
    "anchor_file": _handle_anchor_file,
    "anchor_text": _handle_anchor_text,
    "anchor_json": _handle_anchor_json,
    "lookup_hash": _handle_lookup_hash,
    # chain_confirm_bundle is the canonical name; verify_bundle is the
    # legacy alias name (deprecated 0.3, fail-closed 0.4, removable 0.5).
    # The alias no longer routes to chain_confirm — it fail-closes with a
    # structured redirect (deprecated_tool_blocked) because routing to
    # chain-only under a name that implies full verify was the v0.2
    # false-PASS class. chain_confirm_bundle itself still accepts either
    # `bundle_path` or `path` in args.
    "chain_confirm_bundle": _handle_chain_confirm_bundle,
    "verify_bundle": _handle_verify_bundle_blocked,
    "verify_file_against_bundle": _handle_verify_file_against_bundle,
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
                        ) -> mtypes.CallToolResult:
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
