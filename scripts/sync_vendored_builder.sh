#!/usr/bin/env bash
# sync_vendored_builder.sh — re-vendor the JS disclosure-builder snapshot from a
# monorepo checkout. Thin wrapper over sync_vendored_builder.py (the real logic:
# transitive .mjs closure -> flatten + repoint imports -> stamp SOURCE_COMMIT ->
# node --check). Maintainer gesture; NOT run in CI.
#
# Usage:
#   scripts/sync_vendored_builder.sh [/path/to/moltbook-monorepo]
#   SATSIGNAL_MONOREPO=/path/to/monorepo scripts/sync_vendored_builder.sh
#
# After syncing: re-run the test suite and, if shipping, bump the version +
# refresh the 0.x CHANGELOG note about the new SOURCE_COMMIT.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

ARGS=()
if [[ "${1:-}" != "" ]]; then
  ARGS+=(--monorepo "$1")
fi

exec "$PY" "$HERE/sync_vendored_builder.py" "${ARGS[@]}"
