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

## Configuration

| Env var | Required | Default |
|---|---|---|
| `SATSIGNAL_API_KEY`  | for anchoring | — |
| `SATSIGNAL_API_BASE` | no | `https://proof.satsignal.cloud` |
| `SATSIGNAL_MATTER`   | no | `inbox` |

Get an API key at <https://proof.satsignal.cloud>.

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
        "SATSIGNAL_MATTER": "case-123"
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

- The `label`, `filename`, and `matter_slug` fields you pass are written
  into the receipt and rendered on the public verifier page. They are
  also attacker-controllable from any agent calling this server —
  downstream code that reads these fields should treat them as untrusted
  text (HTML-escape, never embed in LLM context without an isolation
  boundary).
- The API key is sent as `Authorization: Bearer …` over HTTPS and is
  never logged or returned in tool output.

## License

MIT.
