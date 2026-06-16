# Vendored disclosure-builder snapshot

This directory is a **vendored, flattened snapshot** of the Satsignal JS
disclosure-builder, copied from the monorepo by
`scripts/sync_vendored_builder.py`. The disclosable-* MCP tools shell out to it
(via `node_bridge.py` -> `mcp_disclosure_cli.mjs`).

**Do not hand-edit these files.** They are a copy, not the source of truth.
Per monorepo decision 0023 there is ONE implementation of the leaf / RFC-8785
JCS / duplicate-last Merkle / HKDF per-leaf-salt crypto — the JS under
`src/satsignal_notary/web/static/disclosure-builder/` (+ the `packages/
disclosure-redact/` glue). To pick up upstream changes, re-run the sync script
against a monorepo checkout; it rewrites every file plus `SOURCE_COMMIT`.

`SOURCE_COMMIT` records the monorepo commit this snapshot was taken from — a
parity test asserts it is present and a 40-hex hash, so a snapshot can never
ship without provenance. `mcp_disclosure_cli.mjs` is the ONE hand-written file
here (the thin JSON stdio entrypoint); it is not overwritten by the sync.
