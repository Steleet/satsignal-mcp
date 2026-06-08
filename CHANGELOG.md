# Changelog

## 0.5.5

Bugfix. `chain_confirm_bundle` now confirms the current v2 (`schema_version: 2`) standard `.mbnt` bundles the live notary emits — previously it returned `no_file_sha` for all of them. Behavior change on the previously-broken path only; everything else is wire-identical to 0.5.4. Released 2026-06-08.

- **`chain_confirm_bundle` reads the v2 byte-exact file sha, not the legacy flat field (Issue C, external tester report — satsignal-cli 0.4.3 / satsignal-mcp 0.5.4).** The handler read the subject file hash from `canonical.subject.document_sha256`, but v2 canonical docs store it at `canonical.subject.proofs.byte_exact.hash`. Every current standard bundle therefore confirmed as `no_file_sha`, even though `verify_file_against_bundle` handled the same bundles correctly — which is what masked it as a behavior quirk rather than a stale-shape assumption.
  - **Fix:** new `_subject_file_sha()` resolves the v2 `proofs.byte_exact.hash` location first and falls back to the legacy flat `document_sha256`, so old bundles keep confirming. Sealed (`content_canonical` commitment) and manifest (`chunk_merkle` root) bundles still correctly return `no_file_sha` — neither carries a naked, lookup-able file hash.
  - **Why it slipped through:** the test suite built bundles with the stale `document_sha256` shape. The default test bundle is now the v2 `byte_exact` shape; added a v2 regression test and an explicit legacy-fallback test. Full suite 100 passing.
  - **Behavior-change framing:** callers confirming current bundles were already broken (always `no_file_sha`); they now confirm correctly — fix-not-break, but it IS a behavior change for anyone who special-cased the spurious `no_file_sha`.

## 0.5.4

Ships the cluster j + cluster l fixes from the 2026-05-23 LOW sweep. Patch bump — docs + schema-description + classifier additions only; no behavior change in the MCP tool surface. Wire-shape byte-identical to 0.5.3. Released 2026-05-23 (intra-day follow-up to 0.5.3).

- **`anchor_json` schema-description names the `string_coerced_data` error code (V1-L1).** The `data` property's description now names the structured error code that the 0.5.2 handler guard already returns, so MCP hosts that string-coerce structured args can trace the resulting `isError=true` response back to the schema rather than chasing it through the handler source. Cold-start probe rerun, 2026-05-22; PR #13 squash `cbad959`.
- **README states the Python floor (V1-L2).** Install section now explicitly states `Requires Python 3.10 or newer.`, matching the floor that's already pinned in `pyproject.toml`. Same PR.
- **README documents tool-schema inspection (V1-L3).** New `## Inspecting tool schemas` section explains how to extract schemas via the `_tool_definitions()` function, with a caveat that the leading underscore signals implementation-detail status — stable-API consumers should use the MCP protocol's `list_tools` request. Same PR.
- **RELEASE.md attestation framing points at the canonical surfaces (V4-L2).** "What a third party can verify today" digest line now points at the canonical PEP 691 simple-index JSON for machine-verifiable attestation lookups; the legacy `/pypi/<pkg>/json` endpoint is retained only as a fallback with an explicit "predates PEP 740" framing. Same PR.
- **`Development Status :: 4 - Beta` classifier declared (V4-L3).** `pyproject.toml` classifiers now declare `Development Status :: 4 - Beta`, matching the rest of the Satsignal package family (`satsignal-otel` already declared; `satsignal-cli` adding the same declaration in its concurrent 0.4.3 release). PR #14 squash `eedee12`.

## 0.5.3

Documentation-only correction. Wire-shape byte-identical to 0.5.2. Released 2026-05-23.

- **Provenance-status framing corrected (erratum for 0.5.2 / 0.5.1 / 0.5.0 / 0.4.1 release notes).** Earlier release notes claimed the Sigstore attestation guarantee was "staged but not yet delivered to the end-user-visible surface" because the gating signal was `pypi.org/pypi/satsignal-mcp/<ver>/json` reporting `provenance: null`. That was the wrong signal — the legacy warehouse JSON predates PEP 740 and never carried PEP 740 metadata. The canonical surfaces are the PEP 691 simple-index JSON at `https://pypi.org/simple/satsignal-mcp/` (`files[].provenance` field) and the PEP 740 integrity endpoint at `https://pypi.org/integrity/satsignal-mcp/<ver>/<file>/provenance`. Both have been populated since 0.4.1. PEP 740 attestations on satsignal-mcp are therefore live and machine-verifiable today, and have been since 0.4.1. Only the human-readable badge on the PyPI project-page UI (`pypi.org/project/satsignal-mcp/<ver>/`) is not yet rendered; that is a separate PyPI roadmap item and does not block today's verification.
- **Worked example, 0.5.2:** predicate type `https://docs.pypi.org/attestations/publish/v1`; subject sha256 `cc781461f023457b5acca28e63cf52e2662afc2cbc9c32b9a86e4be6a392d466` (matches the wheel `satsignal_mcp-0.5.2-py3-none-any.whl` byte-exactly); certificate Subject Alternative Name binds to `https://github.com/Steleet/satsignal-mcp/.github/workflows/publish.yml@refs/tags/v0.5.2` and Actions run `26317880691`; Rekor `logIndex` 1609430725, kind `dsse`.
- **`RELEASE.md` updated** to reflect the corrected framing: the "Sigstore attestations" section now describes the two delivery surfaces (machine-verifiable: live; human-readable badge: pending) and gives the verification path with the 0.5.2 example. The "0.5.1 explicit-`attestations: true` pilot" narrative is retired — the attestation was already being published correctly from 0.4.1 onward; the pilot was answering a question that wasn't broken.
- Older CHANGELOG entries (0.5.2, 0.5.1, 0.5.0, 0.4.1) are intentionally left untouched as historical record. This 0.5.3 entry is the erratum.

## 0.5.2

Cluster D from the 2026-05-22 cold-start probe. Closes one HIGH and two MEDIUM findings. Wire-shape impact only on the previously-broken `anchor_json` bug path. Released 2026-05-22.

- **`anchor_json` no longer silently anchors a wrong sha when an MCP host string-coerces structured arguments (H#16).** Two-part fix:
  - **Schema:** the `data` property now declares `"type": ["object", "array", "string", "number", "boolean", "null"]` (JSON Schema's "any JSON value"). Pre-0.5.2 the property omitted `type` entirely, letting non-spec-validating hosts transport the value as its JSON-encoded string form without surfacing the violation. Spec-conformant clients that validate against the (newly explicit) schema see no change to their previously-successful calls.
  - **Handler guard:** before any canonicalize / network call, if `data` arrives as a string that `json.loads` parses to a non-string value (dict / list / number / bool / null), the tool returns a structured error with `code="string_coerced_data"` and a message explaining the host-side transport bug, instead of canonicalizing the escaped-quoted string form and anchoring those bytes on-chain. Strings that parse as JSON strings, or don't parse at all, flow through as before — the caller genuinely meant to anchor a string.
  - **Behavior change framing:** clients that were hitting the bug path were already broken (anchoring a different sha than the agent intended, silently). They now fail loudly with `isError=true` and `code="string_coerced_data"` instead — fix-not-break, but it IS a behavior change for callers who were relying on the (buggy) implicit transport coercion. Clients sending structured `data` correctly see no change.
  - **New error code:** `string_coerced_data` (added to the small set of `_error_response` codes — joins `missing_data`, `canonicalization_failed`, `conflicting_alias`).
  - Regression tests cover the five non-string parsed types, dry-run + real-anchor mode, and the three fall-through paths (string-of-string, unparseable, structured value).
- **RELEASE.md "Honest status" paragraph refreshed (M#23).** Was pinned to 0.4.1 / 2026-05-21; now reflects the 0.5.1 explicit-`attestations: true` pilot result — provenance is still null on PyPI, the implicit-vs-explicit hypothesis is disconfirmed, root cause lies elsewhere. The OIDC publish guarantee remains live; the Sigstore attestation guarantee remains staged-but-not-delivered.
- **README "Verification model" paragraph tightened (M#24).** Was claiming each anchor returns `proof_id` + `proof_url` (carrying the legacy `bundle_id` / `receipt_url`). The wire response carries only the legacy names — `bundle_id` and `receipt_url` — and the `proof_*` rename lives in `proof.satsignal.cloud`'s UI / marketing layer, not in the MCP response. README now describes the actual response honestly. No wire change.

This release does NOT fix the PyPI `provenance: null` issue (separate; tracked).

## 0.5.1

Release-infrastructure pilot. No user-visible behavior change; tool surface byte-identical to 0.5.0. Released 2026-05-22.

- **Explicit `attestations: true` on `pypa/gh-action-pypi-publish@release/v1`.** Sets the input explicitly in `.github/workflows/publish.yml` rather than relying on the action's documented default. Tests a hypothesis surfaced during a 2026-05-22 investigation: three prior PyPI releases (mcp 0.4.1, mcp 0.5.0, satsignal-cli 0.4.2) all shipped with no Sigstore attestation visible on PyPI (`provenance: null` / `urls[].provenance` absent), despite the action's run log showing attestation generation + Rekor anchoring + clean exit. PyPI's `/integrity/.../provenance` endpoint returns 404 for all six prior artifacts. The Trusted Publisher row on PyPI has the correct `Environment name: pypi`, so the asymmetry (upload accepted, attestation silently dropped) suggests either an implicit-vs-explicit default-resolution gap in the action or a stale PyPI publisher binding. This release tests the first hypothesis.
- Tool surface unchanged from 0.5.0 (seven tools, six callable + one fail-closed `verify_bundle` redirect; removal still scheduled for a later 0.5.x).

## 0.5.0

Two cold-start LOW findings closed (Probe c). MCP API conformance + JCS
spec-conformance fix.

- **MCP error signal (`isError`).** All tool handlers now return
  `CallToolResult` with `isError: true` on the error path (was bare
  `list[TextContent]` with the error code in the JSON body but no
  isError flag). Programmatic clients branching on `result.isError`
  now correctly distinguish error from success. The text body shape is
  unchanged: error payload is still `{"error": "<code>", "message":
  "<human>", ...}`. Naive clients that ignored isError see no change;
  clients that respect the flag (per MCP protocol) gain correct error
  detection.
- **Canonicalize: full RFC 8785 JCS.** `satsignal_mcp.canonicalize`
  now implements full JCS: NFC-normalize string values and dict
  keys; sort dict keys by UTF-16-BE byte order (not simple
  lexicographic). Previous impl used `json.dumps(sort_keys=True, …)`
  which agrees with JCS for ASCII-only payloads but diverges on any
  document with multibyte unicode (combining diacritics, rare
  scripts). The CLI's RFC 8785 impl has been the authoritative
  reference all along; satsignal-mcp was non-compliant. **Wire
  impact:** the canonical bytes for non-ASCII payloads change, so the
  sha256 changes, so bundles anchored via satsignal-mcp ≤0.4.1 with
  non-ASCII content will NOT verify with satsignal-mcp ≥0.5.0 (or
  with satsignal-cli, which they already didn't). ASCII-only bundles
  are byte-identical. Cross-tool interop bug closed.

New regression tests cover both behaviors (CallToolResult isError flag
+ JCS unicode handling: NFC, UTF-16-BE sort, multibyte values, plus
cross-validation against satsignal-cli's authoritative `_jcs`).

## 0.4.1

Maintenance release — no user-visible behavior change. Tool surface
byte-identical to 0.4.0.

- `__version__` now reads from package metadata
  (`importlib.metadata.version("satsignal-mcp")`) instead of a
  hard-coded literal. `pyproject.toml` is the single source of truth
  (matches `satsignal-cli`). New `tests/test_version.py` asserts the
  resolved string matches the installed dist (PR #7).
- First release published via PyPI Trusted Publishers (OIDC); new
  `.github/workflows/publish.yml` handshakes with PyPI directly on
  `release: published`. No API tokens, no `~/.pypirc` (PR #6).
- Tool surface unchanged from 0.4.0 (seven tools, six callable + one
  fail-closed `verify_bundle` redirect; removal scheduled for 0.5.x).

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
