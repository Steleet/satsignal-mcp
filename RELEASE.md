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

## Sigstore attestations (configured; not yet live)

The publish job also declares `permissions: attestations: write`, and `pypa/gh-action-pypi-publish@release/v1` defaults `attestations: true`. The intent is that each upload carries a Sigstore attestation visible on the PyPI release page — provable to come from this exact workflow run.

**Honest status as of `satsignal-mcp` 0.5.1 (published 2026-05-22):** PyPI's JSON API at `https://pypi.org/pypi/satsignal-mcp/0.5.1/json` still reports `provenance: null` for both the sdist and the wheel. 0.5.1 was a deliberate pilot — it set `attestations: true` *explicitly* on `pypa/gh-action-pypi-publish@release/v1` rather than relying on the action's documented default, testing the hypothesis that an implicit-vs-explicit default-resolution gap was eating the attestation. The 0.5.1 publish did NOT resolve the issue: provenance remains null on PyPI, so the hypothesis is disconfirmed and the root cause lies elsewhere (stale Trusted Publisher binding or a PyPI-side ingest gap is the next likely candidate). 0.5.2 ships under the same publish pipeline; this paragraph will be updated when `provenance:` is non-null on the JSON API.

The OIDC publish guarantee (no maintainer token, no shared secret) is live and verifiable today. The Sigstore attestation guarantee (independently-verifiable build provenance) is staged but not yet delivered to the end-user-visible surface. This doc will be updated when `provenance:` is non-null on the JSON API.

## Build flow

- `uv build` in the `build` job produces both an sdist and a wheel.
- The wheel is smoke-imported in an isolated `uv venv` venv before the publish job sees it.
- Build artifacts are uploaded across jobs via `actions/upload-artifact` / `actions/download-artifact` so the publish job runs without the build job's permissions.

Actions are pinned to **major-tag form** (`@v4`, `@v5`, `@release/v1`), not SHA-pinned. This protects against accidental action deletion but not against a compromised action publisher pushing a malicious patch under the same major tag.

## What a third party can verify today

- The release tag exists on `Steleet/satsignal-mcp` and matches the PyPI version.
- The published artifacts' sha256 digests are reproduced in the PyPI JSON API at `https://pypi.org/pypi/satsignal-mcp/<version>/json` under `urls[].digests.sha256`.
- The workflow file at `.github/workflows/publish.yml` on the matching commit reads as advertised.
- *(Future, once attestations land on PyPI)* The Sigstore attestation on the PyPI release page will bind the wheel + sdist to a specific GitHub Actions workflow run.

## See also

- Project trust-surface narrative: <https://satsignal.cloud/docs.html#how-we-publish>.
- PyPI Trusted Publishers reference: <https://docs.pypi.org/trusted-publishers/>.
- Sigstore + PyPI attestations: <https://docs.pypi.org/attestations/>.
