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

Vocabulary (decision 0046 — canonical proof/folder names): the public
input name is `folder` (env SATSIGNAL_FOLDER). `matter` /
SATSIGNAL_MATTER are the frozen legacy aliases — still accepted with
byte-identical behavior. On the wire to the Satsignal API the body key
is the canonical `folder_slug`; tool results use the canonical
`proof_id` / `folder_slug` / `proof_url` keys. Responses from the API
are read canonical-first with a legacy-key fallback (bundle_id /
matter_slug / receipt_url) for older / self-hosted servers. If both
`folder` and `matter` are sent with non-empty values that DIFFER, the
tool returns a validation error (conflicting_alias, mirroring the
server) rather than silently picking one.

Tools (v0.7):
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
  anchor_disclosable           Anchor a SEALED, selectively-disclosable
                               envelope (per-leaf commitments). node>=18.
  create_disclosure            Redact an anchored source .mbnt to reveal a
                               chosen subset (local-only). node>=18.
  verify_disclosure            Verify a disclosure binds to its committed
                               root (cryptographic bind). node>=18.

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
from .node_bridge import NodeBridgeError, NodeUnavailable, run_disclosure_op


_SERVER_NAME = "satsignal"

_INSTRUCTIONS = (
    "Satsignal anchors a sha256 of your input to the BSV blockchain, "
    "returning a proof that the anchorer held this exact "
    "input by a specific time (tamper-evidence and timing — not "
    "authorship, and not that the input existed before the anchor). "
    "Use anchor_file / anchor_text / anchor_json to create a proof. "
    "To check a proof, use verify_file_against_bundle when you have "
    "the original file in hand (full verify: detects tampering) — or "
    "chain_confirm_bundle for a fast chain-only check when the file "
    "isn't available. lookup_hash is a raw sha → txid index lookup. "
    "Each anchor call broadcasts a real on-chain transaction and "
    "counts against the workspace's daily quota — pass dry_run=true "
    "first if you want to preview the sha256 before committing. "
    "For SELECTIVE DISCLOSURE: anchor_disclosable seals a payload as "
    "per-leaf commitments; create_disclosure reveals a chosen subset "
    "(the rest stays sealed but provably present-but-hidden); "
    "verify_disclosure checks a disclosure binds to the committed "
    "root. A disclosure proves the revealed fields are authentic to "
    "the sealed commitment — not that the content is true. These "
    "three require node>=18 on PATH (or SATSIGNAL_NODE)."
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
            "honored) or 'inbox'. Sent to the API as the canonical "
            "`folder_slug` wire field."
        ),
    }
    matter_field = {
        "type": "string",
        "description": (
            "Legacy alias of `folder`; still accepted. Prefer "
            "`folder`. Sending both with different non-empty values "
            "is an error (conflicting_alias); equal values are "
            "accepted."
        ),
    }
    label_field = {
        "type": "string",
        "description": (
            "Optional short label shown on the proof. "
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
            "sha256_hex in the same folder returns the prior proof "
            "without broadcasting. force_new=true opts out — useful "
            "for refreshing the chain timestamp."
        ),
    }
    return [
        mtypes.Tool(
            name="anchor_file",
            description=(
                "Anchor a local file: compute its sha256, POST to "
                "Satsignal, return the proof. The file's bytes never "
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
                "caller can save them alongside the proof — "
                "verification later requires reproducing the same bytes."
            ),
            inputSchema={
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": {
                        # JSON Schema "any JSON value" — spell out the full
                        # type union so spec-conformant validators surface
                        # the violation when a host string-coerces what
                        # should be a structured value. Pre-0.5.2 this
                        # property had no `type` at all; some MCP hosts
                        # (notably Claude Desktop in certain configs)
                        # silently transported structured args as their
                        # JSON-encoded string form, producing a different
                        # canonical sha than the caller intended. The
                        # handler also runs a string-coercion-detection
                        # guard as a belt-and-braces second line.
                        "type": [
                            "object", "array", "string",
                            "number", "boolean", "null",
                        ],
                        "description": (
                            "Any JSON value (object, array, string, "
                            "number, bool, null). NaN / Infinity / "
                            "non-string keys are rejected. If your "
                            "MCP host string-coerces structured "
                            "args, this tool returns "
                            "code=\"string_coerced_data\" with "
                            "isError=true rather than silently "
                            "anchoring the JSON-encoded string's "
                            "bytes; pass dict / list directly."
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
                "no auth required. Returns {hit, proof_id, txid, "
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
        mtypes.Tool(
            name="anchor_disclosable",
            description=(
                "Anchor a payload as a SEALED, selectively-disclosable envelope "
                "(the golden-wedge scheme). Unlike anchor_text/anchor_json which "
                "anchor a flat digest, this splits the payload into per-leaf "
                "commitments under one Merkle root, so ANY subset can later be "
                "revealed and still verify against the same on-chain commitment. "
                ".txt -> text-tree-v1; .json -> json-ast-v1 (override via "
                "`granularity`). Hashing + envelope build happen LOCALLY in a "
                "vendored Node builder (requires node>=18 on PATH or SATSIGNAL_NODE) "
                "— only the root is broadcast, the content never leaves this "
                "machine, and the master salt is never returned. Writes a source "
                ".mbnt (all leaves, sealed). Pass `reveal`/`reveal_names` to ALSO "
                "emit a one-shot disclosure in the same call (requires "
                "storage='mirror'). Proves the anchorer HELD this exact input by a "
                "specific time (tamper-evidence + timing) — NOT authorship, NOT "
                "that it pre-existed the anchor. Each live anchor broadcasts one "
                "on-chain tx and counts against the daily quota; pass dry_run=true "
                "to preview scheme/leaf_count/root with no spend."
            ),
            inputSchema={
                "type": "object",
                "required": ["file_path"],
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .txt or .json file to anchor.",
                    },
                    "granularity": {
                        "type": "string",
                        "enum": ["tree", "ast"],
                        "description": (
                            "Override the extension default (.txt->tree, "
                            ".json->ast). Required for other extensions."
                        ),
                    },
                    "storage": {
                        "type": "string",
                        "enum": ["mirror", "blind"],
                        "default": "mirror",
                        "description": (
                            "mirror (default): the master salt is persisted "
                            "inside the returned source .mbnt so create_disclosure "
                            "can redact later from the .mbnt alone. blind: the "
                            "salt stays local (never uploaded) — higher secrecy, "
                            "but later redaction needs the salt supplied "
                            "separately. Content is local in both modes."
                        ),
                    },
                    "reveal": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0},
                        "description": (
                            "Optional. If set, ALSO emit a disclosure revealing "
                            "only these 0-based leaf indices (everything else "
                            "sealed). Requires storage='mirror'. Mutually "
                            "exclusive with reveal_names."
                        ),
                    },
                    "reveal_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional. Like reveal but by selector: json-ast-v1 "
                            "RFC-6901 pointers (e.g. /decision/amount_usd) or "
                            "text-tree-v1 slash paths (e.g. /p0). Mutually "
                            "exclusive with reveal."
                        ),
                    },
                    "render_mode": {
                        "type": "string",
                        "enum": ["drop", "mask"],
                        "default": "drop",
                        "description": (
                            "For the one-shot disclosure: how redacted nodes "
                            "render. Presentation-only; the proof is identical."
                        ),
                    },
                    "category": {
                        "type": "string",
                        "description": "Optional category tag on the anchor.",
                    },
                    "create_folder": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "POST /api/v1/folders for the folder before "
                            "anchoring if it does not exist."
                        ),
                    },
                    "out_dir": {
                        "type": "string",
                        "description": (
                            "Output directory for the source .mbnt (and one-shot "
                            "disclosure). Defaults to the input file's directory."
                        ),
                    },
                    "folder": folder_field,
                    "matter": matter_field,
                    "dry_run": dry_run_field,
                },
            },
        ),
        mtypes.Tool(
            name="create_disclosure",
            description=(
                "Produce an audience-specific redacted disclosure from an "
                "already-anchored SOURCE .mbnt: reveal only the selectors you "
                "list, seal everything else. LOCAL ONLY — no network, no on-chain "
                "tx, no quota (the commitment already exists from "
                "anchor_disclosable); redact the same source as many times as you "
                "need for different audiences. Needs the ORIGINAL anchored bytes "
                "plus the source .mbnt, and runs a vendored Node builder "
                "(node>=18). Self-verifies that the result still binds to the "
                "on-chain root before returning. Call with list_only=true first "
                "to enumerate selectors, then pass the subset to reveal. The "
                "emitted .disclosure.mbnt is what you hand a counterparty; they "
                "check it with verify_disclosure."
            ),
            inputSchema={
                "type": "object",
                "required": ["original_path", "source_mbnt_path"],
                "properties": {
                    "original_path": {
                        "type": "string",
                        "description": (
                            "Path to the ORIGINAL file — the exact bytes that "
                            "were anchored (NOT the source .mbnt)."
                        ),
                    },
                    "source_mbnt_path": {
                        "type": "string",
                        "description": (
                            "Path to the source .mbnt produced by "
                            "anchor_disclosable."
                        ),
                    },
                    "reveal": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0},
                        "description": (
                            "0-based leaf indices to REVEAL (everything else "
                            "sealed). Mutually exclusive with reveal_names. "
                            "Required unless list_only."
                        ),
                    },
                    "reveal_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Selectors to REVEAL: json-ast-v1 RFC-6901 pointers "
                            "/ text-tree-v1 slash paths (match the 'selector' "
                            "column from list_only exactly). Mutually exclusive "
                            "with reveal."
                        ),
                    },
                    "render_mode": {
                        "type": "string",
                        "enum": ["drop", "mask"],
                        "default": "drop",
                        "description": (
                            "How redacted nodes render in the view. "
                            "Presentation-only; the proof is identical either way."
                        ),
                    },
                    "out_dir": {
                        "type": "string",
                        "description": (
                            "Output directory. Defaults to the original file's "
                            "directory."
                        ),
                    },
                    "list_only": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "If true, enumerate every leaf (index, selector, "
                            "leaf_id, value preview) and return — writes nothing, "
                            "reveals nothing. Use to pick reveal values."
                        ),
                    },
                },
            },
        ),
        mtypes.Tool(
            name="verify_disclosure",
            description=(
                "Verify a redacted disclosure .mbnt: confirm every REVEALED leaf "
                "cryptographically binds to the committed Merkle root claimed by "
                "the disclosure's linked_anchor, the carrier matches the "
                "disclosure's claimed canonical hash, profile/algo bind, and (if "
                "view_path is given) the redacted view's sha256 matches. Returns "
                "verified=true/false (a failed bind is verified=false, NOT a tool "
                "error). Proves the revealed fields are authentic to the sealed "
                "commitment and the sealed fields are provably present-but-hidden "
                "(not added/removed after anchoring) — it does NOT prove the "
                "content was true, nor that it pre-existed the anchor. Runs a "
                "vendored Node builder (node>=18). NOTE: this is the cryptographic "
                "bind; on-chain existence is reported via linked_txid + root for "
                "you to confirm on a BSV explorer (sealed anchors are not indexed "
                "by lookup_hash)."
            ),
            inputSchema={
                "type": "object",
                "required": ["disclosure_mbnt_path"],
                "properties": {
                    "disclosure_mbnt_path": {
                        "type": "string",
                        "description": "Path to the .disclosure.mbnt to verify.",
                    },
                    "view_path": {
                        "type": "string",
                        "description": (
                            "Optional path to the redacted view file; if given, "
                            "its sha256 is checked against the disclosure's "
                            "presentation.view_sha256."
                        ),
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


def _anchor_result_payload(*, sha: str, folder: str, label: str | None,
                            file_size: int | None,
                            anchor) -> dict:
    # Canonical output vocabulary (decision 0046): proof_id /
    # folder_slug / proof_url. The legacy bundle_id / matter_slug /
    # receipt_url output keys are gone as of 0.6.0.
    return {
        "anchored": True,
        "sha256_hex": sha,
        "proof_id": anchor.proof_id,
        "txid": anchor.txid,
        "mode": anchor.mode,
        "folder_slug": anchor.folder_slug,
        "proof_url": anchor.proof_url,
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
            "folder_slug": folder,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. Pass dry_run=false (or omit) to broadcast."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            folder_slug=folder,
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
        sha=sha, folder=folder, label=label, file_size=size, anchor=anchor,
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
    label = args.get("label") or None
    dry_run = bool(args.get("dry_run", False))
    force_new = bool(args.get("force_new", False))

    if dry_run:
        return _text_response({
            "anchored": False,
            "dry_run": True,
            "sha256_hex": sha,
            "byte_length": size,
            "folder_slug": folder,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. The sha256 covers exactly "
                "text.encode('utf-8'). Pass dry_run=false to broadcast."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            folder_slug=folder,
            sha256_hex=sha,
            file_size=size,
            label=label,
            force_new=force_new,
        )
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    return _text_response(_anchor_result_payload(
        sha=sha, folder=folder, label=label, file_size=size, anchor=anchor,
    ))


async def _handle_anchor_json(args: dict, api: SatsignalApi
                              ) -> mtypes.CallToolResult:
    if "data" not in args:
        return _error_response("data is required", code="missing_data")
    # String-coercion guard: some MCP hosts string-coerce structured tool
    # arguments at transport time, so a caller-intended dict / list / etc
    # arrives here as its JSON-encoded string form. Canonicalizing that
    # string produces the canonical bytes of the *escaped-quoted string*,
    # not of the structured value — a silently-wrong sha gets anchored.
    # If `data` is a string that parses as JSON to a non-string value,
    # refuse loudly BEFORE any network call. Strings that legitimately
    # round-trip as JSON-strings (or that don't parse at all) fall through
    # to the existing canonicalize path — the caller meant to anchor a
    # string. See H#16 in the 2026-05-22 cold-start probe.
    raw_data = args["data"]
    if isinstance(raw_data, str):
        try:
            parsed = json.loads(raw_data)
        except (ValueError, TypeError):
            parsed = raw_data  # genuine string payload — fall through
        if not isinstance(parsed, str):
            parsed_type = type(parsed).__name__
            return _error_response(
                f"data was sent as a string that parses as a JSON "
                f"{parsed_type}. This is usually caused by an MCP host "
                f"string-coercing structured arguments at transport "
                f"time. Send the raw {parsed_type} as `data`, not its "
                f"JSON-encoded string form. If you genuinely intended "
                f"to anchor the literal JSON string, encode it as a "
                f"JSON-string-of-a-string (e.g. `\"\\\"{{...}}\\\"\"`) "
                f"or use anchor_text instead.",
                code="string_coerced_data",
                parsed_json_type=parsed_type,
            )
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
            "folder_slug": folder,
            **({"label": label} if label else {}),
            "note": (
                "Dry run only. Save the canonical_bytes alongside the "
                "future proof — verification requires reproducing "
                "these exact bytes."
            ),
        })

    try:
        anchor = await api.anchor_standard(
            folder_slug=folder,
            sha256_hex=sha,
            file_size=size,
            label=label,
            force_new=force_new,
        )
    except ApiError as e:
        return _error_response(e.message or str(e), code=e.code,
                               status=e.status, body=e.body)
    payload = _anchor_result_payload(
        sha=sha, folder=folder, label=label, file_size=size, anchor=anchor,
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
        # Canonical key first; legacy bundle_id fallback covers older /
        # self-hosted servers (and proof.* mirror-mode lags).
        "proof_id": result.get("proof_id") or result.get("bundle_id"),
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


def _subject_file_sha(subject: dict) -> str | None:
    """Resolve the 64-hex file sha256 from a canonical-doc subject.

    v2 canonical docs (schema_version 2 — what the live notary emits)
    store the file hash at ``subject.proofs.byte_exact.hash`` (algo
    sha256). Pre-v2 bundles carried it flat at
    ``subject.document_sha256``. Try the v2 location first, then fall
    back to the legacy field. Returns the 64-hex string, or None when
    neither is present — sealed bundles expose only a
    ``content_canonical`` commitment and manifest bundles only a
    ``chunk_merkle`` root, neither of which is a naked, lookup-able
    file sha.

    (Reading only the legacy field was the 0.5.4 bug: every current
    standard bundle has schema_version 2, so chain_confirm_bundle
    returned no_file_sha for bundles that verify_file_against_bundle
    handled fine.)
    """
    proofs = subject.get("proofs")
    if isinstance(proofs, dict):
        byte_exact = proofs.get("byte_exact")
        if isinstance(byte_exact, dict) and byte_exact.get("algo") == "sha256":
            h = byte_exact.get("hash")
            if isinstance(h, str) and len(h) == 64:
                return h
    legacy = subject.get("document_sha256")
    if isinstance(legacy, str) and len(legacy) == 64:
        return legacy
    return None


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

    # The 64-hex file sha is what /lookup_hash indexes. In v2 canonical
    # docs it lives at canonical.subject.proofs.byte_exact.hash; pre-v2
    # bundles carried it flat at canonical.subject.document_sha256
    # (_subject_file_sha resolves both). manifest.doc_hash_expected is a
    # 40-hex truncated hash of the canonical doc embedded on-chain (the
    # OP_RETURN payload), NOT the file hash — not lookup-able.
    subject = canonical.get("subject") or {}
    claimed_sha = _subject_file_sha(subject)
    if claimed_sha is None:
        return _error_response(
            "bundle has no byte_exact file sha in canonical.subject "
            "(sealed or manifest-mode bundles don't expose a naked file "
            "sha; chain-confirm via lookup_hash isn't applicable).",
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
        # Canonical-first read with legacy fallback (older servers).
        "proof_id": result.get("proof_id") or result.get("bundle_id"),
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


# ─────────────── disclosable-* tools (vendored-node-backed) ─────────────
# anchor_disclosable / create_disclosure / verify_disclosure delegate the
# sealed-envelope build, redaction, and disclosure-bind verification to the
# VENDORED JS source of truth via node_bridge (decision 0023 — one JS
# implementation of the leaf / RFC-8785 JCS / duplicate-last Merkle / HKDF
# per-leaf-salt crypto; a Python re-port would risk a one-byte divergence from
# the on-chain anchor). node>=18 is a host prerequisite the package cannot
# pip-install; its absence is the fail-closed `node_unavailable` code, never a
# silent skip. All input validation short-circuits BEFORE any node spawn.

_STORAGE_MODES = ("mirror", "blind")
_GRANULARITIES = ("tree", "ast")


async def _run_node_op(op: str, params: dict, *, api_key: str | None = None
                       ) -> tuple[dict | None, mtypes.CallToolResult | None]:
    """Run a node disclosure op off the event loop (mirrors how
    verify_file_against_bundle threads its blocking verify). Returns
    (data, None) on success or (None, error_result) on a handled failure,
    translating NodeUnavailable / NodeBridgeError into the wire vocabulary
    (carrying the JS fail_code / error_class as extras)."""
    try:
        data = await asyncio.to_thread(
            run_disclosure_op, op, params, api_key=api_key)
        return data, None
    except NodeUnavailable as e:
        return None, _error_response(e.message, code="node_unavailable")
    except NodeBridgeError as e:
        extras: dict[str, Any] = {}
        if e.fail_code:
            extras["fail_code"] = e.fail_code
        if e.error_class:
            extras["error_class"] = e.error_class
        return None, _error_response(e.message, code=e.code, **extras)


def _valid_reveal_indices(reveal: Any) -> bool:
    # bool is a subclass of int — exclude it explicitly so True/False can't pass.
    return (isinstance(reveal, list) and len(reveal) > 0
            and all(isinstance(i, int) and not isinstance(i, bool) and i >= 0
                    for i in reveal))


def _valid_reveal_names(names: Any) -> bool:
    return (isinstance(names, list) and len(names) > 0
            and all(isinstance(n, str) for n in names))


async def _handle_anchor_disclosable(args: dict, api: SatsignalApi
                                     ) -> mtypes.CallToolResult:
    raw_path = args.get("file_path") or ""
    if not isinstance(raw_path, str) or not raw_path:
        return _error_response("file_path is required",
                               code="missing_file_path")
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return _error_response(f"not a file: {path}", code="not_a_file",
                               which="file_path")
    try:
        folder = _resolve_folder(args)
    except FolderAliasConflict as e:
        return _error_response(str(e), code="conflicting_alias")

    storage = args.get("storage") or "mirror"
    if storage not in _STORAGE_MODES:
        return _error_response(
            f"storage must be one of {_STORAGE_MODES} (got {storage!r})",
            code="bad_storage")
    granularity = args.get("granularity")
    if granularity is not None and granularity not in _GRANULARITIES:
        return _error_response(
            f"granularity must be one of {_GRANULARITIES} (got {granularity!r})",
            code="bad_granularity")
    dry_run = bool(args.get("dry_run", False))

    reveal = args.get("reveal")
    reveal_names = args.get("reveal_names")
    has_reveal = bool(reveal) or bool(reveal_names)
    if reveal and reveal_names:
        return _error_response(
            "pass either reveal (indices) or reveal_names (selectors), not both",
            code="conflicting_selectors")
    if reveal is not None and not _valid_reveal_indices(reveal):
        return _error_response(
            "reveal must be a non-empty list of non-negative integers",
            code="bad_reveal_index")
    if reveal_names and not _valid_reveal_names(reveal_names):
        return _error_response(
            "reveal_names must be a non-empty list of strings",
            code="bad_reveal_names")
    if has_reveal and dry_run:
        return _error_response(
            "a one-shot disclosure (reveal/reveal_names) needs a real anchor "
            "and is not available with dry_run",
            code="reveal_requires_anchor")
    if has_reveal and storage == "blind":
        return _error_response(
            "blind storage omits the master salt from the source .mbnt, so a "
            "one-shot disclosure cannot be built from it. Use storage='mirror' "
            "for the one-shot reveal, or anchor blind and run create_disclosure "
            "later with the salt supplied out-of-band.",
            code="cannot_redact_blind")

    api_key = None if dry_run else _env_api_key()
    if not dry_run and not api_key:
        return _error_response(
            "SATSIGNAL_API_KEY is required to anchor (not needed for dry_run)",
            code="missing_api_key")

    params: dict[str, Any] = {
        "file_path": str(path),
        "folder_slug": folder,
        "storage": storage,
        "dry_run": dry_run,
        "base": _env_api_base(),
    }
    if granularity:
        params["granularity"] = granularity
    if args.get("category"):
        params["category"] = args["category"]
    if args.get("create_folder"):
        params["create_folder"] = True
    if args.get("out_dir"):
        params["out_dir"] = str(Path(args["out_dir"]).expanduser())

    data, err = await _run_node_op("anchor", params, api_key=api_key)
    if err:
        return err

    payload: dict[str, Any] = {
        "anchored": not dry_run,
        "scheme": data.get("scheme"),
        "leaf_count": data.get("leafCount"),
        "root": data.get("root"),
        "folder_slug": folder,
        "storage": storage,
    }
    if dry_run:
        payload["dry_run"] = True
        if "body" in data:
            payload["preview_body"] = data["body"]
        payload["note"] = (
            "Dry run only: the sealed envelope was built locally; nothing was "
            "broadcast and no quota was spent. The master salt is never "
            "returned (salt_b64 is redacted in preview_body).")
        return _text_response(payload)

    verify = data.get("verify")
    if isinstance(verify, dict) and verify.get("ok") is False:
        return _error_response(
            "anchor self-verify failed: the served .mbnt does not bind to the "
            "anchored file",
            code="self_verify_failed", fail_code=verify.get("fail_code"))

    payload.update({
        "proof_id": data.get("proof_id"),
        "txid": data.get("txid"),
        "source_mbnt_path": data.get("sourceMbntPath"),
        "self_verify": verify,
    })

    # One-shot disclosure: orchestrated as a separate local `create` op against
    # the just-written source .mbnt (no key, no network, no extra spend). The
    # live anchor has ALREADY broadcast and passed self-verify by this point, so
    # a failure of the (re-runnable, local) disclosure must NOT be surfaced as a
    # tool error — that would discard proof_id/txid/source_mbnt_path and could
    # push a caller to re-anchor (a duplicate on-chain spend). Embed the
    # disclosure outcome instead and keep the anchor result a success.
    if has_reveal:
        create_params: dict[str, Any] = {
            "original_path": str(path),
            "source_mbnt_path": data.get("sourceMbntPath"),
        }
        if reveal:
            create_params["reveal"] = reveal
        if reveal_names:
            create_params["reveal_names"] = reveal_names
        if args.get("render_mode"):
            create_params["render_mode"] = args["render_mode"]
        ddata, derr = await _run_node_op("create", create_params)
        if derr:
            derr_body = json.loads(derr.content[0].text)
            payload["disclosure"] = {
                "error": derr_body.get("error"),
                "message": derr_body.get("message"),
                **({"fail_code": derr_body["fail_code"]}
                   if "fail_code" in derr_body else {}),
                "note": ("the on-chain anchor SUCCEEDED; re-run create_disclosure "
                         "against source_mbnt_path to produce the disclosure "
                         "locally (no re-anchor needed)"),
            }
            return _text_response(payload)
        dverify = ddata.get("self_verify")
        disclosure = {
            "redacted_copy_path": ddata.get("redacted_copy_path"),
            "disclosure_mbnt_path": ddata.get("disclosure_mbnt_path"),
            "revealed_count": ddata.get("revealed_count"),
            "self_verify": dverify,
        }
        if isinstance(dverify, dict) and dverify.get("ok") is False:
            # Defensive: a non-binding one-shot disclosure should be impossible
            # (the source was just built), but flag it rather than imply success
            # — without failing the already-sound on-chain anchor.
            disclosure["error"] = "self_verify_failed"
            disclosure["message"] = (
                "one-shot disclosure did not bind to the committed root; the "
                "on-chain anchor itself is sound")
        payload["disclosure"] = disclosure
    return _text_response(payload)


async def _handle_create_disclosure(
    args: dict, api: SatsignalApi,  # api unused — local-only, no network/key
) -> mtypes.CallToolResult:
    raw_orig = args.get("original_path") or ""
    raw_src = args.get("source_mbnt_path") or ""
    if not isinstance(raw_orig, str) or not raw_orig:
        return _error_response("original_path is required",
                               code="missing_original_path")
    if not isinstance(raw_src, str) or not raw_src:
        return _error_response("source_mbnt_path is required",
                               code="missing_source_mbnt_path")
    orig = Path(raw_orig).expanduser()
    src = Path(raw_src).expanduser()
    if not orig.is_file():
        return _error_response(f"not a file: {orig}", code="not_a_file",
                               which="original_path")
    if not src.is_file():
        return _error_response(f"not a file: {src}", code="not_a_file",
                               which="source_mbnt_path")
    if not zipfile.is_zipfile(src):
        return _error_response(f"{src} is not a .mbnt (ZIP) bundle",
                               code="not_a_bundle")

    if bool(args.get("list_only", False)):
        data, err = await _run_node_op("list", {
            "original_path": str(orig),
            "source_mbnt_path": str(src),
        })
        if err:
            return err
        return _text_response({
            "scheme": data.get("scheme"),
            "leaf_count": data.get("leaf_count"),
            "leaves": data.get("leaves"),
        })

    reveal = args.get("reveal")
    reveal_names = args.get("reveal_names")
    if reveal and reveal_names:
        return _error_response(
            "pass either reveal (indices) or reveal_names (selectors), not both",
            code="conflicting_selectors")
    if not reveal and not reveal_names:
        return _error_response(
            "one of reveal, reveal_names, or list_only is required",
            code="missing_reveal")
    if reveal is not None and not _valid_reveal_indices(reveal):
        return _error_response(
            "reveal must be a non-empty list of non-negative integers",
            code="bad_reveal_index")
    if reveal_names and not _valid_reveal_names(reveal_names):
        return _error_response(
            "reveal_names must be a non-empty list of strings",
            code="bad_reveal_names")
    render_mode = args.get("render_mode") or "drop"
    if render_mode not in ("drop", "mask"):
        return _error_response("render_mode must be 'drop' or 'mask'",
                               code="bad_render_mode")

    params: dict[str, Any] = {
        "original_path": str(orig),
        "source_mbnt_path": str(src),
        "render_mode": render_mode,
    }
    if reveal:
        params["reveal"] = reveal
    if reveal_names:
        params["reveal_names"] = reveal_names
    if args.get("out_dir"):
        params["out_dir"] = str(Path(args["out_dir"]).expanduser())

    data, err = await _run_node_op("create", params)
    if err:
        return err
    verify = data.get("self_verify")
    if isinstance(verify, dict) and verify.get("ok") is False:
        return _error_response(
            "disclosure self-verify failed: the redacted view does not bind to "
            "the committed root",
            code="self_verify_failed", fail_code=verify.get("fail_code"))
    return _text_response({
        "redacted_copy_path": data.get("redacted_copy_path"),
        "disclosure_mbnt_path": data.get("disclosure_mbnt_path"),
        "root": data.get("root"),
        "revealed_count": data.get("revealed_count"),
        "self_verify": verify,
    })


async def _handle_verify_disclosure(
    args: dict, api: SatsignalApi,  # api unused — read-only, no key
) -> mtypes.CallToolResult:
    raw = args.get("disclosure_mbnt_path") or ""
    if not isinstance(raw, str) or not raw:
        return _error_response("disclosure_mbnt_path is required",
                               code="missing_disclosure_path")
    path = Path(raw).expanduser()
    if not path.is_file():
        return _error_response(f"not a file: {path}", code="not_a_file",
                               which="disclosure_mbnt_path")
    if not zipfile.is_zipfile(path):
        return _error_response(f"{path} is not a .mbnt (ZIP) bundle",
                               code="not_a_bundle")
    params: dict[str, Any] = {"disclosure_mbnt_path": str(path)}
    raw_view = args.get("view_path")
    if isinstance(raw_view, str) and raw_view:
        view = Path(raw_view).expanduser()
        if not view.is_file():
            return _error_response(f"not a file: {view}", code="not_a_file",
                                   which="view_path")
        params["view_path"] = str(view)

    data, err = await _run_node_op("verify", params)
    if err:
        return err
    verified = bool(data.get("verified"))
    payload: dict[str, Any] = {
        "verified": verified,
        "scheme": data.get("scheme"),
        "root": data.get("root"),
        "linked_txid": data.get("linked_txid"),
        "carrier_sha256": data.get("carrier_sha256"),
        "revealed_count": data.get("revealed_count"),
        "view_checked": data.get("view_checked"),
        # HONESTY: this is the cryptographic bind only. lookup_hash cannot
        # confirm sealed/deep-content anchors (no naked file sha is indexed —
        # the same reason chain_confirm_bundle returns no_file_sha for them), so
        # on-chain existence is surfaced for external confirmation, not asserted.
        "chain_confirmation": {
            "checked_here": False,
            "how": ("Confirm on-chain by looking up linked_txid on a BSV "
                    "explorer and checking its OP_RETURN commits to `root`."),
        },
    }
    if not verified:
        payload["reason"] = data.get("fail_code")
    return _text_response(payload)


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
    # disclosable-* tools — sealed selective-disclosure, backed by the
    # vendored JS builder via node_bridge.py (node>=18 host prerequisite).
    "anchor_disclosable": _handle_anchor_disclosable,
    "create_disclosure": _handle_create_disclosure,
    "verify_disclosure": _handle_verify_disclosure,
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
