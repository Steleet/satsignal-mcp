# Changelog

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
