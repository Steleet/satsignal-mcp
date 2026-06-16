#!/usr/bin/env python3
"""Vendor a self-contained snapshot of the Satsignal JS disclosure-builder.

The disclosable-* MCP tools shell out to the JavaScript builder rather than
re-porting its leaf/JCS/Merkle crypto to Python (monorepo decision 0023 — one
JS source of truth). Because satsignal-mcp ships as a standalone PyPI/pipx
package with no access to the monorepo, the builder must be VENDORED: copied,
flattened into one directory, and have its monorepo-relative imports repointed
to local siblings so node can load it standalone.

This script is the reproducible sync tool. It:
  1. computes the FULL transitive .mjs closure from the package-glue
     entrypoints (following both static `from "..."` and dynamic `import()`),
  2. flattens every file into the vendor dir, repointing each relative import
     to `./<basename>.mjs`,
  3. collapses the `anchor-pack.mjs` shim/real collision in favour of the real
     disclosure-builder module,
  4. stamps SOURCE_COMMIT (monorepo HEAD) so a vendored snapshot can never ship
     without provenance, and refreshes VENDOR.md + the ESM marker,
  5. `node --check`s every copied file and flags any non-builtin, non-relative
     import it could not resolve.

Repointing rewrites ONLY module-resolution paths, never logic — the .mjs source
is not a hash preimage (the crypto runs over file CONTENT supplied at runtime),
so a vendored snapshot stays byte-identical to the on-chain builder.

Usage:
    python3 scripts/sync_vendored_builder.py [--monorepo PATH] [--check-only]
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# Entrypoints the vendored node CLI imports from (relative to the monorepo).
# index.mjs is the aggregator that re-exports verify/redact/pack/merkle/etc;
# the three glue modules add the file-I/O wrappers. Their closure is a superset
# of everything mcp_disclosure_cli.mjs can reach.
_ENTRYPOINTS = [
    "packages/disclosure-redact/index.mjs",
    "packages/disclosure-redact/anchor-to-mbnt.mjs",
    "packages/disclosure-redact/redact-from-mbnt.mjs",
    "packages/disclosure-redact/mbnt-read.mjs",
]

# When two source files flatten to the same basename, prefer the file whose
# path contains this fragment (the real source-of-truth) over the other (a thin
# re-export shim under packages/). Today the only collision is anchor-pack.mjs.
_PREFER_DIR_FRAGMENT = "/web/static/disclosure-builder/"

# Matches the specifier in `... from "X"`, `import("X")`, `import "X"`.
_SPEC_RE = re.compile(
    r"""(?P<pre>(?:from|import)\s*\(?\s*["'])(?P<spec>[^"']+)(?P<post>["'])"""
)


def _specifiers(text: str) -> list[str]:
    return [m.group("spec") for m in _SPEC_RE.finditer(text)]


def _is_relative_mjs(spec: str) -> bool:
    return spec.endswith(".mjs") and (spec.startswith("./") or spec.startswith("../"))


def _resolve(spec: str, from_file: Path) -> Path:
    return (from_file.parent / spec).resolve()


def compute_closure(monorepo: Path) -> tuple[dict[str, Path], list[str]]:
    """BFS the import graph. Returns (basename -> chosen source path) and a list
    of human-readable notes (collisions resolved, unresolved/flagged specs)."""
    notes: list[str] = []
    seen: set[Path] = set()
    chosen: dict[str, Path] = {}
    queue: list[Path] = []

    for ep in _ENTRYPOINTS:
        p = (monorepo / ep).resolve()
        if not p.is_file():
            raise SystemExit(f"entrypoint missing: {p}")
        queue.append(p)

    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if not cur.is_file():
            raise SystemExit(f"closure references missing file: {cur}")
        text = cur.read_text(encoding="utf-8")
        base = cur.name

        if base in chosen and chosen[base] != cur:
            # Collision: keep the preferred (real) module, drop the other.
            a, b = chosen[base], cur
            real = a if _PREFER_DIR_FRAGMENT in str(a) else (
                b if _PREFER_DIR_FRAGMENT in str(b) else a)
            dropped = b if real == a else a
            chosen[base] = real
            notes.append(f"collision {base}: kept {real} | dropped {dropped}")
        else:
            chosen[base] = cur

        for spec in _specifiers(text):
            if spec.startswith("node:"):
                continue
            if _is_relative_mjs(spec):
                queue.append(_resolve(spec, cur))
            elif not spec.startswith(".") and not spec.startswith("node:"):
                notes.append(f"FLAG bare specifier {spec!r} in {cur.name}")
            elif spec.startswith(".") and not spec.endswith(".mjs"):
                notes.append(f"FLAG extensionless relative {spec!r} in {cur.name}")
    return chosen, notes


def repoint(text: str) -> str:
    def _sub(m: re.Match) -> str:
        spec = m.group("spec")
        if _is_relative_mjs(spec):
            return f"{m.group('pre')}./{os.path.basename(spec)}{m.group('post')}"
        return m.group(0)
    return _SPEC_RE.sub(_sub, text)


_VENDOR_MD = """# Vendored disclosure-builder snapshot

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
"""


def write_outputs(dest: Path, chosen: dict[str, Path], monorepo: Path,
                  notes: list[str]) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    # Remove only previously-vendored .mjs (preserve the hand-written CLI +
    # docs); we re-derive the vendored set every run.
    cli = "mcp_disclosure_cli.mjs"
    for old in dest.glob("*.mjs"):
        if old.name != cli:
            old.unlink()

    for base, src in sorted(chosen.items()):
        (dest / base).write_text(repoint(src.read_text(encoding="utf-8")),
                                 encoding="utf-8")

    commit = subprocess.run(
        ["git", "-C", str(monorepo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    (dest / "SOURCE_COMMIT").write_text(commit + "\n", encoding="utf-8")
    (dest / "VENDOR.md").write_text(_VENDOR_MD, encoding="utf-8")
    (dest / "package.json").write_text(
        '{\n  "type": "module",\n  "private": true,\n'
        '  "description": "Vendored Satsignal disclosure-builder snapshot. '
        'Do not edit; see VENDOR.md."\n}\n', encoding="utf-8")

    print(f"vendored {len(chosen)} module(s) -> {dest}")
    print(f"SOURCE_COMMIT = {commit}")
    for n in notes:
        print("  note:", n)


def node_check(dest: Path) -> int:
    node = os.environ.get("SATSIGNAL_NODE") or "node"
    failures = 0
    for f in sorted(dest.glob("*.mjs")):
        r = subprocess.run([node, "--check", str(f)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            failures += 1
            print(f"  node --check FAIL {f.name}: {r.stderr.strip()}")
    print(f"node --check: {'all OK' if not failures else f'{failures} FAILED'}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--monorepo", default=os.environ.get(
        "SATSIGNAL_MONOREPO",
        "/home/eric/Satsignal/root/moltbook-social-media-agent"))
    ap.add_argument("--dest", default=str(
        Path(__file__).resolve().parent.parent
        / "src" / "satsignal_mcp" / "vendor" / "disclosure_builder"))
    ap.add_argument("--check-only", action="store_true",
                    help="only run node --check on the existing vendor dir")
    args = ap.parse_args()

    dest = Path(args.dest)
    if args.check_only:
        return 1 if node_check(dest) else 0

    monorepo = Path(args.monorepo).resolve()
    chosen, notes = compute_closure(monorepo)
    write_outputs(dest, chosen, monorepo, notes)
    return 1 if node_check(dest) else 0


if __name__ == "__main__":
    sys.exit(main())
