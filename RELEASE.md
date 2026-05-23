# How we publish `satsignal-mcp`

This document records the supply-chain story for the `satsignal-mcp` package on PyPI: how a release reaches PyPI, what evidence accompanies it, and what a third party can verify without trusting the maintainer.

It is the pilot for the project's three published packages — `satsignal-mcp`, `satsignal-cli`, `satsignal-otel`. The other two adopt the same pattern: a separate `publish.yml` per repo, byte-identical except for the package-name smoke import.

## Release trigger

Releases are cut by `gh release create vX.Y.Z --generate-notes`. The `release: published` event fires `.github/workflows/publish.yml`. There is no tag-push backdoor — pushing a `vX.Y.Z` tag without creating a GitHub release does not trigger a publish.

A separate `.github/workflows/anchor.yml` fires on tag push and dogfoods the project's own anchoring service against each release tag, giving the release a tamper-evident timing claim independent of GitHub. The two workflows run on distinct trigger surfaces so they cannot race.

## Token-less publish (PyPI Trusted Publishers / OIDC)

The publish job declares `permissions: id-token: write` and runs in a GitHub Environment named `pypi`. GitHub Actions mints a short-lived OIDC token for the job; PyPI accepts uploads carrying that token because the `satsignal-mcp` project on PyPI has a Trusted Publisher entry configured with:

- Publisher: GitHub Actions
- Owner: `Steleet`
- Repository: `satsignal-mcp`
- Workflow filename: `publish.yml`
- Environment name: `pypi`

The publish step uses `pypa/gh-action-pypi-publish@release/v1` with **no `password:` field** — its presence would silently disable OIDC. (`satsignal-otel`'s first-attempt workflow had `password: secrets.PYPI_API_TOKEN` next to `id-token: write` and never published anything before the migration; tracked under `Steleet/satsignal-otel#2`.)

What this means for an integrator:

- There is no long-lived `PYPI_API_TOKEN` on a maintainer's machine to leak, no `~/.pypirc`, no shared team secret.
- Revocation is a single action in the PyPI UI (remove the Trusted Publisher entry); no token-rotation choreography.

## Sigstore attestations

The publish job declares `permissions: attestations: write`, and `pypa/gh-action-pypi-publish@release/v1` defaults `attestations: true`. Each upload carries a PEP 740 Sigstore attestation that binds the artifact to the exact GitHub Actions workflow run that produced it.

**Status as of `satsignal-mcp` 0.5.4 (2026-05-23):** PEP 740 attestations have been live and machine-verifiable since 0.4.1. The verification path is:

1. Fetch the PEP 691 simple-index JSON: `GET https://pypi.org/simple/satsignal-mcp/` with `Accept: application/vnd.pypi.simple.v1+json`. Each entry in `files[]` from 0.4.1 onward carries a populated `provenance` URL.
2. Fetch the PEP 740 integrity endpoint at that URL — pattern `https://pypi.org/integrity/satsignal-mcp/<version>/<filename>/provenance`, Content-Type `application/vnd.pypi.integrity.v1+json`. The response is a Sigstore attestation bundle.
3. Verify the bundle: the Sigstore certificate's Subject Alternative Name must bind the artifact to the expected workflow identity; the Rekor transparency-log entry must include the bundle; the attestation subject's sha256 must equal the artifact's sha256.

Worked example, `satsignal-mcp` 0.5.2:

- Predicate type: `https://docs.pypi.org/attestations/publish/v1`
- Subject: `satsignal_mcp-0.5.2-py3-none-any.whl`, sha256 `cc781461f023457b5acca28e63cf52e2662afc2cbc9c32b9a86e4be6a392d466` (matches the wheel byte-exactly)
- Certificate SAN: `https://github.com/Steleet/satsignal-mcp/.github/workflows/publish.yml@refs/tags/v0.5.2` and `https://github.com/Steleet/satsignal-mcp/actions/runs/26317880691/attempts/1`
- Rekor entry: `logIndex` 1609430725, kind `dsse`, integrated 2026-05-23
- Publisher: `{kind: GitHub, environment: pypi, repository: Steleet/satsignal-mcp, workflow: publish.yml}`

The human-readable badge on `https://pypi.org/project/satsignal-mcp/<version>/` is not yet rendered — that surface is a separate PyPI roadmap item and will appear when PyPI ships it. It does not block today's verification. Separately, the legacy warehouse JSON at `https://pypi.org/pypi/satsignal-mcp/<version>/json` still reports `provenance: null` for every release file; that endpoint predates PEP 740 and is not the canonical attestation surface — we no longer use it as a gating signal.

An earlier doc described an explicit-`attestations: true` pilot in 0.5.1 premised on `pypi.org/pypi/.../json` reporting `provenance: null` as a regression signal. The probe in 0.5.3 corrected the framing: that endpoint never carried PEP 740 metadata. The canonical surfaces are the PEP 691 simple-index JSON and the PEP 740 integrity endpoint, both populated since 0.4.1.

Both the OIDC publish guarantee (no maintainer token, no shared secret) and the Sigstore attestation guarantee (independently-verifiable build provenance) are live and verifiable today on the machine-readable surface. Only the human-readable PyPI project-page badge is pending; this doc will be updated when that UI ships.

## Build flow

- `uv build` in the `build` job produces both an sdist and a wheel.
- The wheel is smoke-imported in an isolated `uv venv` venv before the publish job sees it.
- Build artifacts are uploaded across jobs via `actions/upload-artifact` / `actions/download-artifact` so the publish job runs without the build job's permissions.

Actions are pinned to **major-tag form** (`@v4`, `@v5`, `@release/v1`), not SHA-pinned. This protects against accidental action deletion but not against a compromised action publisher pushing a malicious patch under the same major tag.

## What a third party can verify today

- The release tag exists on `Steleet/satsignal-mcp` and matches the PyPI version.
- The published artifacts' sha256 digests are reproduced in the PEP 691 simple-index JSON at `https://pypi.org/simple/satsignal-mcp/` (with `Accept: application/vnd.pypi.simple.v1+json`), under `files[].hashes.sha256`. This is the same surface that carries `files[].provenance` (the PEP 740 attestation URL), so a verifier can read digest + attestation pointer in a single fetch. The legacy `https://pypi.org/pypi/satsignal-mcp/<version>/json` endpoint also returns the digests under `urls[].digests.sha256`, but it predates PEP 740 and does NOT carry attestation metadata — for machine-verifiable attestation discovery, use the simple-index JSON and the PEP 740 integrity endpoint (`https://pypi.org/integrity/satsignal-mcp/<version>/<filename>/provenance`).
- The workflow file at `.github/workflows/publish.yml` on the matching commit reads as advertised.
- The Sigstore attestation at `https://pypi.org/integrity/satsignal-mcp/<version>/<filename>/provenance` (URL discoverable from the PEP 691 simple-index JSON's `files[].provenance` field) binds the wheel + sdist to a specific GitHub Actions workflow run via the Sigstore certificate's Subject Alternative Name and a Rekor transparency-log entry. Live since 0.4.1.

## See also

- Project trust-surface narrative: <https://satsignal.cloud/docs.html#how-we-publish>.
- PyPI Trusted Publishers reference: <https://docs.pypi.org/trusted-publishers/>.
- Sigstore + PyPI attestations: <https://docs.pypi.org/attestations/>.
