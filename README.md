# satsignal-mcp

MCP server exposing Satsignal tamper-evident anchoring as agent-callable tools.

Any MCP-compatible client (Claude Desktop, Claude Code, agent frameworks that
speak MCP over stdio) can call Satsignal directly — no custom SDK required.

## What it does

Each anchor call computes a sha256 of the input client-side and sends only
the hash to `proof.satsignal.cloud`. The file/text/JSON bytes never leave
the calling machine. The server records the hash on the BSV blockchain
and returns a proof the agent can save or pass on.

## Tools

| Tool | Auth | What it does |
|---|---|---|
| `anchor_file`                | yes | sha256 a local file, anchor the digest |
| `anchor_text`                | yes | sha256 a UTF-8 string, anchor the digest |
| `anchor_json`                | yes | canonicalize JSON (sorted keys, compact, UTF-8), sha256, anchor |
| `lookup_hash`                | no  | check if a sha256 is on-chain |
| `verify_file_against_bundle` | no  | **full verify** — re-hash the original file, confirm it matches the bundle, chain-confirm via public block explorers. Detects file tampering. |
| `chain_confirm_bundle`       | no  | chain-confirm only — open a local `.mbnt`, extract sha+txid, confirm via `lookup_hash`. Fast, but does NOT detect file tampering. |
| `verify_bundle`              | no  | _deprecated + fail-closed_ (v0.4) — returns `deprecated_tool_blocked` error directing to `verify_file_against_bundle` or `chain_confirm_bundle`. Removable in 0.5. |

`anchor_*` tools accept `dry_run: true` to preview the sha256 without
broadcasting. The Satsignal API itself does **not** honor `dry_run` —
the flag lives in this MCP layer and short-circuits before any network
call.

### Folder selection

Each `anchor_*` tool accepts a `folder` property naming the workspace
folder the proof lands in (defaults to `SATSIGNAL_FOLDER`, then the
legacy `SATSIGNAL_MATTER`, then `inbox`). The request sent to the
Satsignal API uses the canonical `folder_slug` wire field.

> **Legacy compat:** the old input name `matter` is still accepted as a
> silent alias of `folder`. Sending both with different non-empty
> values is rejected (`conflicting_alias`, mirroring the server); equal
> values are accepted.

## Configuration

| Env var | Required | Default |
|---|---|---|
| `SATSIGNAL_API_KEY`  | for anchoring | — |
| `SATSIGNAL_API_BASE` | no | `https://app.satsignal.cloud` |
| `SATSIGNAL_FOLDER`   | no | `inbox` |
| `SATSIGNAL_MATTER`   | no | legacy alias of `SATSIGNAL_FOLDER` (still honored; `SATSIGNAL_FOLDER` wins if both set) |

Get an API key at <https://app.satsignal.cloud>. The customer API
(`POST /api/v1/anchors`, bundle download, dashboard) lives on
`app.satsignal.cloud`. `proof.satsignal.cloud` is the public verifier
surface and serves `/lookup_hash` in mirror-mode — `chain_confirm_bundle`
works against either host, but anchoring requires `app.*`. v0.1.0
shipped with the wrong default and silently 404'd every anchor call.

## Install

Requires Python 3.10 or newer.

```bash
pip install satsignal-mcp
```

## Inspecting tool schemas

The MCP tool schemas are built inline by `_tool_definitions()` in
`src/satsignal_mcp/server.py` — they are not exposed as a static
module-level binding. If you need a JSON dump (for static analysis,
IDE autocomplete config, or tooling that pre-validates calls), call
the function directly:

```python
import json
from satsignal_mcp.server import _tool_definitions

tools = _tool_definitions()
print(json.dumps(
    [{"name": t.name,
      "description": t.description,
      "inputSchema": t.inputSchema}
     for t in tools],
    indent=2,
))
```

`_tool_definitions()` returns `list[mcp.types.Tool]`; the leading
underscore reflects that the function is an implementation detail of
the server, not a stable export. If you build tooling against it,
pin to a specific `satsignal-mcp` version or run the MCP server and
read tools via the protocol's `list_tools` request — the latter is
the contract guaranteed to stay stable across releases.

## Claude Desktop config

Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "satsignal": {
      "command": "satsignal-mcp",
      "env": {
        "SATSIGNAL_API_KEY": "sk_...",
        "SATSIGNAL_FOLDER": "case-123"
      }
    }
  }
}
```

### Why the `env` block matters (host env-var binding)

MCP hosts (Claude Desktop, Claude Code, agent frameworks) typically
strip or rebind environment variables at server-launch time — so a
`SATSIGNAL_API_KEY` set in the operator's shell does NOT reliably
propagate into the MCP server process. Bind the key **explicitly**
inside the `env` block of the host's config (as shown above); do
not assume process-env inheritance.

If anchor calls return `401 unauthorized` despite the key being
visible in your shell (`echo $SATSIGNAL_API_KEY` works), this is
almost certainly the cause — check the host's config block, not the
shell environment.

## Verification model

Each anchor returns `proof_id`, `txid`, and `proof_url` — the
canonical vocabulary the Satsignal API itself now emits. The proof is
independent of Satsignal: anyone can fetch the bundle, verify the
on-chain transaction directly against BSV, and check the sha256
matches.

> **Compatibility note (0.6.0, vocabulary sunset):** this server sends
> the canonical request key (`folder_slug`) and reports canonical
> result keys (`proof_id` / `folder_slug` / `proof_url`); the legacy
> `bundle_id` / `matter_slug` / `receipt_url` keys are gone from tool
> output. Legacy *inputs* (`matter`, `SATSIGNAL_MATTER`) remain
> accepted as silent aliases. When talking to an older / self-hosted
> Satsignal server that still emits the legacy response keys, this
> server reads them as a fallback and re-emits them under the
> canonical names — but anchoring against a server too old to accept
> `folder_slug` requires satsignal-mcp ≤ 0.5.x.

This server exposes two verify tools with different trust assumptions —
pick the one that matches what you have on hand:

- **`verify_file_against_bundle(file_path, bundle_path)`** — full
  verify. Re-hashes the original file, confirms it matches the bundle's
  claimed sha (crypto check, detects tampering), then chain-confirms via
  public block explorers (WoC + Bitails) that the on-chain `doc_hash`
  matches the bundle. This is the recommended path when you have the
  original file. Backed by `satsignal-cli`'s `verify_file` (pinned as a
  runtime dep so a clean install gets full verify out of the box).
- **`chain_confirm_bundle(bundle_path)`** — fast chain-confirm only.
  Opens the bundle, extracts its claimed `sha + txid`, and confirms
  via Satsignal's `/lookup_hash` index that the sha was anchored at
  that txid. Does NOT open the original file, so a **tampered original
  is not detected** — the bundle stays self-consistent. Use this when
  the original file isn't available, or as a cheap pre-check.

`verify_bundle` in v0.3 silently aliased `chain_confirm_bundle`,
preserving v0.2's false-PASS class on tampered originals (a host that
strips tool descriptions wouldn't see the deprecation warning). In v0.4
the alias fail-closes — every call returns a `deprecated_tool_blocked`
structured error directing the caller at the right tool. The tool
remains listed so callers pinned by name get the redirect rather than
`unknown_tool`. Full removal lands in 0.5.

## Security notes

- The `label`, `filename`, and `folder` (sent on the wire as the
  canonical `folder_slug`) fields you pass are written
  into the proof and rendered on the public verifier page. They are
  also attacker-controllable from any agent calling this server —
  downstream code that reads these fields should treat them as untrusted
  text (HTML-escape, never embed in LLM context without an isolation
  boundary).
- The API key is sent as `Authorization: Bearer …` over HTTPS and is
  never logged or returned in tool output.

## License

MIT.
