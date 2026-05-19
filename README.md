# satsignal-mcp

MCP server exposing Satsignal tamper-evident anchoring as agent-callable tools.

Any MCP-compatible client (Claude Desktop, Claude Code, agent frameworks that
speak MCP over stdio) can call Satsignal directly — no custom SDK required.

## What it does

Each anchor call computes a sha256 of the input client-side and sends only
the hash to `proof.satsignal.cloud`. The file/text/JSON bytes never leave
the calling machine. The server records the hash on the BSV blockchain
and returns a receipt the agent can save or pass on.

## Tools

| Tool | Auth | What it does |
|---|---|---|
| `anchor_file`     | yes | sha256 a local file, anchor the digest |
| `anchor_text`     | yes | sha256 a UTF-8 string, anchor the digest |
| `anchor_json`     | yes | canonicalize JSON (sorted keys, compact, UTF-8), sha256, anchor |
| `lookup_hash`     | no  | check if a sha256 is on-chain |
| `verify_bundle`   | no  | open a local `.mbnt` and chain-confirm via `lookup_hash` |

`anchor_*` tools accept `dry_run: true` to preview the sha256 without
broadcasting. The Satsignal API itself does **not** honor `dry_run` —
the flag lives in this MCP layer and short-circuits before any network
call.

### Folder selection

Each `anchor_*` tool accepts a `folder` property naming the workspace
folder the receipt lands in (defaults to `SATSIGNAL_FOLDER`, then the
legacy `SATSIGNAL_MATTER`, then `inbox`).

> **Legacy compat:** the old input name `matter` is a frozen alias of
> `folder` — still accepted with byte-identical behavior and never
> removed. Sending both `folder` and `matter` with different non-empty
> values is rejected (`folder_matter_conflict`); equal values are
> accepted. The request sent to the Satsignal API still uses the frozen
> `matter_slug` wire field, so this MCP server keeps working against
> current and older / self-hosted Satsignal servers.

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
surface and serves `/lookup_hash` in mirror-mode — `verify_bundle`
works against either host, but anchoring requires `app.*`. v0.1.0
shipped with the wrong default and silently 404'd every anchor call.

## Install

```bash
pip install satsignal-mcp
```

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

## Verification model

Each anchor returns a `bundle_id`, `txid`, and `receipt_url`. The proof
is independent of Satsignal: anyone can fetch the bundle, verify the
on-chain transaction directly against BSV, and check the sha256 matches.
`satsignal-cli` performs the full cryptographic + chain verification;
`verify_bundle` in this MCP server does a faster chain-confirm only
(matches the bundle's claimed `txid` against what the public
`/lookup_hash` index reports for that sha).

## Security notes

- The `label`, `filename`, and `folder` (sent on the wire as the frozen
  `matter_slug`) fields you pass are written
  into the receipt and rendered on the public verifier page. They are
  also attacker-controllable from any agent calling this server —
  downstream code that reads these fields should treat them as untrusted
  text (HTML-escape, never embed in LLM context without an isolation
  boundary).
- The API key is sent as `Authorization: Bearer …` over HTTPS and is
  never logged or returned in tool output.

## License

MIT.
