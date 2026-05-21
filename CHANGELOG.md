# Changelog

## 0.4.0

Fail-close the deprecated `verify_bundle` alias — closes the v0.2
false-PASS class.

A 2026-05-21 cold-start review (six-vector probe, finding 5) flagged
that the deprecated `verify_bundle` alias in v0.3 still produced
`verified=true` on tampered originals: the alias kept its v0.2
chain-only semantics under a name that implied full verify. The
deprecation description warned LLMs, but a host that strips tool
descriptions reintroduces the trap. This is the exact failure class
v0.3's verify split was meant to retire — v0.3 retired it for the new
canonical names, but not for the legacy alias.

- **`verify_bundle` now fail-closes.** The tool is still listed (so
  callers pinned by name don't get `unknown_tool`), but every call
  returns a structured error (`code="deprecated_tool_blocked"`) naming
  the failure class and directing the caller to:
  - `verify_file_against_bundle(file_path, bundle_path)` — full
    verify (detects file tampering); the safe default.
  - `chain_confirm_bundle(bundle_path)` — chain-confirm only; same
    semantics `verify_bundle` used to provide, under an accurate name.
- The error payload includes `deprecated_tool`, `full_verify_tool`,
  `chain_only_tool`, and `removal_version` fields so a programmatic
  caller can introspect and migrate without parsing the message.
- No change to `chain_confirm_bundle` or `verify_file_against_bundle`
  behavior — they keep v0.3.0 semantics byte-identically.
- Removal schedule unchanged: full alias removal lands in 0.5.x; 0.4.x
  keeps the structured-error stub so callers see the redirect, not
  `unknown_tool`.

## 0.3.0

Verify split — additive new tool + safer naming. Fully
backward-compatible; `verify_bundle` keeps working byte-identically.

A fresh cold-start review (2026-05-20) flagged that `verify_bundle`
sounded like full verify but only did chain-confirm — it never opened
the original file, so a tampered original passed `verified=true`. The
description was honest about this at the tail; the name was not. v0.3
splits the two responsibilities into distinct, accurately-named tools.

- New tool **`verify_file_against_bundle(file_path, bundle_path)`** —
  the safe default for "is this file really what the bundle claims?".
  Re-hashes the original file, compares to the bundle's claimed sha
  (crypto check, detects tampering), then chain-confirms via public
  block explorers (WoC + Bitails) that the on-chain `doc_hash` matches.
  Backed by `satsignal-cli`'s `verify_file` — pinned as a runtime dep
  (`satsignal-cli>=0.4`) so a clean install gets the full verify story
  out of the box.
- New tool name **`chain_confirm_bundle(bundle_path)`** for the
  chain-only behavior previously called `verify_bundle`. Tool
  description now leads with "CHAIN-CONFIRM ONLY: ... does NOT detect
  file tampering". Accepts `bundle_path` (new canonical name) or the
  legacy `path` alias; sending both with different non-empty values is
  rejected (`conflicting_alias`).
- **`verify_bundle` is now a deprecated alias of `chain_confirm_bundle`** —
  same handler, byte-identical behavior, no schema changes for callers
  pinned to it. Removable in 0.5; tool description marks it DEPRECATED
  so listings make the deprecation visible.
- `_INSTRUCTIONS` (the per-server hint injected into agent context)
  now points agents at `verify_file_against_bundle` first when they
  have the file in hand.
- Runtime dep added: `satsignal-cli>=0.4`. Its only own dep is
  `requests`; SPV/p2p modules are dormant unless explicitly invoked
  via the standalone CLI.

## 0.2.1

Consistency patch — no behavior change for correct callers.

- The both-aliases-conflict error code is now `conflicting_alias`,
  matching the Satsignal server and every other client surface
  (action / cli / blob / otel / langchain). 0.2.0 emitted a
  non-canonical `folder_matter_conflict`; only the error *code*
  string changed, the loud-reject behavior and message are unchanged.
- `User-Agent` aligned to `0.2.1`.

## 0.2.0

Additive proof/folder vocabulary aliases — fully backward-compatible.

- Add a `folder` input property (alias of the frozen `matter` property)
  on every anchor tool (`anchor_file`, `anchor_text`, `anchor_json`).
- Add the `SATSIGNAL_FOLDER` environment default (preferred over the
  legacy `SATSIGNAL_MATTER`, which keeps working).
- Conflict rule: supplying both `folder`/`SATSIGNAL_FOLDER` and
  `matter`/`SATSIGNAL_MATTER` with different non-empty values is
  rejected before any network call (mirrors the server's
  `conflicting_alias` behavior); equal values are accepted.
- The HTTP request body still sends the frozen `matter_slug` wire
  token, so this release works unchanged against every Satsignal
  server (including older / self-hosted deployments).
- Align `User-Agent` to the package version (was lagging at `0.1.1`).

Every existing `matter` / `SATSIGNAL_MATTER` configuration keeps
working byte-identically.

## 0.1.3 and earlier

See the git history.
