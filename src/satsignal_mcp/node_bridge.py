"""Subprocess bridge to the vendored Node disclosure builder.

The disclosable-* tools (anchor_disclosable / create_disclosure /
verify_disclosure) delegate sealed-envelope construction, redaction, and
disclosure verification to the *vendored* JavaScript source of truth under
``vendor/disclosure_builder/`` rather than re-implementing the crypto in
Python. This is deliberate (monorepo decision 0023: one JS implementation
of the leaf/JCS/Merkle rules, never a second port): the build side —
native tokenizers, RFC 8785 JCS, duplicate-last Merkle, HKDF per-leaf
salts — exists only in that JS, and a one-byte divergence would produce a
different root than what is anchored on-chain. Shelling out keeps these
tools byte-identical to the on-chain anchor and the parity-tested verifier.

Contract — one JSON request object on stdin, one JSON response object on
stdout (the vendored ``mcp_disclosure_cli.mjs`` enforces "stdout is JSON
only; never the master salt"):

    request  : {"op": "anchor"|"create"|"verify"|"list", ...params}
    response : {"ok": true, ...result}                      (success)
             | {"ok": false, "error_code": str,             (handled error)
                "error_class": str, "message": str,
                "fail_code": str?}

A *verification that returns "not verified"* is a SUCCESS (``ok:true`` with
``verified:false``), mirroring verify_file_against_bundle / chain_confirm —
only structural failures (unreadable bundle, malformed disclosure, a binding
error during build) are ``ok:false``.

node>=18 is a HOST PREREQUISITE the Python package cannot pip-install. Its
absence is a fail-closed :class:`NodeUnavailable`, never a silent skip — the
handlers surface it as the wire code ``node_unavailable``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

# Absolute path to the vendored entrypoint, resolved relative to THIS file so
# it works from a pipx/PyPI install (the .mjs ship inside the wheel via the
# pyproject package-data declaration), an editable checkout, or a zip import.
_CLI_PATH = (
    Path(__file__).resolve().parent
    / "vendor" / "disclosure_builder" / "mcp_disclosure_cli.mjs"
)

# Ops that legitimately need the anchoring bearer token. Everything else
# (redaction, leaf listing, disclosure verify) is local/read-only and the key
# is stripped from the child env so it never reaches a process that has no use
# for it.
_KEY_OPS = frozenset({"anchor"})

_DEFAULT_TIMEOUT = 120.0


class NodeBridgeError(Exception):
    """A disclosure op failed in (or around) the Node subprocess.

    ``code`` is the wire error code the handler surfaces to the MCP client;
    ``fail_code`` carries the disclosure-spec fail string (e.g.
    ``linked_anchor_canonical_hash_mismatch``) when the JS layer supplies one.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        error_class: str | None = None,
        fail_code: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.error_class = error_class
        self.fail_code = fail_code
        self.exit_code = exit_code


class NodeUnavailable(NodeBridgeError):
    """node>=18 was not found on PATH (and SATSIGNAL_NODE is unset/invalid).

    Distinct subclass so handlers can map it to the dedicated, fail-closed
    ``node_unavailable`` wire code without conflating it with a runtime
    failure of an otherwise-present node.
    """


def find_node() -> str | None:
    """Resolve a node binary, or None if unavailable.

    Honors a ``SATSIGNAL_NODE`` override (an explicit path or a name on PATH);
    otherwise falls back to ``node`` on PATH. Returns the resolved executable
    path, or None when nothing usable is found — the caller fail-closes.
    """
    override = os.environ.get("SATSIGNAL_NODE", "").strip()
    if override:
        # An override may be a bare name (resolve via PATH) or an absolute
        # path (accept if it exists and is executable).
        resolved = shutil.which(override)
        if resolved:
            return resolved
        p = Path(override).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        return None
    return shutil.which("node")


def _child_env(op: str, api_key: str | None) -> dict[str, str]:
    """Build the subprocess env: inherit the parent (node needs PATH etc.),
    but only expose the bearer token to ops that anchor — strip it otherwise
    so redaction/verify/list never see a credential they don't use."""
    env = dict(os.environ)
    env.pop("SATSIGNAL_API_KEY", None)
    if op in _KEY_OPS and api_key:
        env["SATSIGNAL_API_KEY"] = api_key
    return env


def run_disclosure_op(
    op: str,
    params: dict,
    *,
    api_key: str | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict:
    """Run one disclosure op in the vendored Node entrypoint and return the
    parsed success payload.

    Blocking (uses ``subprocess.run``); async handlers should wrap it in
    ``asyncio.to_thread`` exactly as verify_file_against_bundle wraps its
    blocking verify call.

    Raises :class:`NodeUnavailable` when no node binary is found, and
    :class:`NodeBridgeError` on timeout, a non-JSON / empty stdout, or an
    ``ok:false`` response (carrying the JS ``error_class`` / ``fail_code``).
    """
    node = find_node()
    if node is None:
        raise NodeUnavailable(
            "node_unavailable",
            "node (>=18) was not found. The disclosable-* tools shell out to "
            "a vendored Node builder; install Node >=18 on PATH or point "
            "SATSIGNAL_NODE at a node binary.",
        )
    if not _CLI_PATH.is_file():
        # Packaging bug: the vendored .mjs did not ship with the wheel.
        raise NodeBridgeError(
            "vendor_missing",
            f"vendored disclosure entrypoint not found at {_CLI_PATH}. The "
            "satsignal-mcp package may have been built without its "
            "vendor/disclosure_builder data files.",
        )

    request = json.dumps({"op": op, **params}).encode("utf-8")
    try:
        proc = subprocess.run(  # noqa: S603 — shell=False, fixed argv
            [node, str(_CLI_PATH)],
            input=request,
            capture_output=True,
            timeout=timeout,
            env=_child_env(op, api_key),
        )
    except subprocess.TimeoutExpired:
        raise NodeBridgeError(
            "node_timeout",
            f"disclosure op {op!r} timed out after {timeout:g}s",
        ) from None

    stdout = proc.stdout.decode("utf-8", "replace").strip()
    stderr = proc.stderr.decode("utf-8", "replace").strip()

    result: object = None
    if stdout:
        try:
            result = json.loads(stdout)
        except ValueError:
            result = None

    if not isinstance(result, dict):
        # No parseable JSON on stdout — a crash, a syntax error in the vendored
        # snapshot, or stderr-only output. Surface stderr (truncated), never
        # the request (it may name a salt-bearing file path).
        detail = stderr or stdout
        raise NodeBridgeError(
            "node_bridge_failed",
            f"disclosure op {op!r} produced no JSON result "
            f"(node exit {proc.returncode}): {detail[:800]}",
            exit_code=proc.returncode,
        )

    if not result.get("ok", False):
        raise NodeBridgeError(
            str(result.get("error_code") or "node_bridge_failed"),
            str(result.get("message") or f"disclosure op {op!r} failed"),
            error_class=result.get("error_class"),
            fail_code=result.get("fail_code"),
            exit_code=proc.returncode,
        )

    return result
