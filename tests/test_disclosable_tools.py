"""Tests for the disclosable-* tools (anchor_disclosable / create_disclosure /
verify_disclosure).

These mock satsignal_mcp.server.run_disclosure_op, so they never spawn node and
never touch the network — exercising the Python handler wiring, validation
short-circuits, error-code mapping, and (security-critical) API-key isolation.
A live anchor is NEVER performed here. The node-backed end-to-end path is
smoke-tested separately and guarded behind node availability.
"""

import asyncio
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from satsignal_mcp import server
from satsignal_mcp.node_bridge import NodeBridgeError, NodeUnavailable

_PATCH = "satsignal_mcp.server.run_disclosure_op"
_VENDOR = Path(server.__file__).resolve().parent / "vendor" / "disclosure_builder"


def _run(coro):
    return asyncio.run(coro)


def _body(result):
    return json.loads(result.content[0].text)


class _Tmp:
    """Make a real .json, a real (valid-zip) .mbnt, and a non-zip file."""

    def __init__(self, tmpdir: Path):
        self.json = tmpdir / "a.json"
        self.json.write_text('{"order_id":"A-100","amount_usd":42.5}')
        self.mbnt = tmpdir / "a.source.mbnt"
        with zipfile.ZipFile(self.mbnt, "w") as z:
            z.writestr("manifest.json", "{}")
            z.writestr("canonical.json", "{}")
            z.writestr("proofs.json", "{}")
        self.notzip = tmpdir / "plain.txt"
        self.notzip.write_text("not a zip")


class SourceCommitProvenanceTest(unittest.TestCase):
    """A vendored snapshot must never ship without provenance."""

    def test_source_commit_present_and_40_hex(self):
        f = _VENDOR / "SOURCE_COMMIT"
        self.assertTrue(f.is_file(), "vendored SOURCE_COMMIT missing")
        commit = f.read_text().strip()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")

    def test_cli_entrypoint_vendored(self):
        self.assertTrue((_VENDOR / "mcp_disclosure_cli.mjs").is_file())


class ValidationShortCircuitTest(unittest.TestCase):
    """Every bad-input case must fail-closed BEFORE any node spawn."""

    def setUp(self):
        self._dir = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        self.t = _Tmp(self._dir)

    def _assert_no_spawn(self, handler, args, code, *, which=None):
        with mock.patch(_PATCH) as m:
            result = _run(handler(args, None))
        m.assert_not_called()
        b = _body(result)
        self.assertTrue(result.isError)
        self.assertEqual(b["error"], code)
        if which:
            self.assertEqual(b.get("which"), which)

    def test_anchor_missing_file_path(self):
        self._assert_no_spawn(server._handle_anchor_disclosable, {}, "missing_file_path")

    def test_anchor_not_a_file(self):
        self._assert_no_spawn(server._handle_anchor_disclosable,
                              {"file_path": "/no/such"}, "not_a_file", which="file_path")

    def test_anchor_bad_storage(self):
        self._assert_no_spawn(server._handle_anchor_disclosable,
                              {"file_path": str(self.t.json), "storage": "weird"},
                              "bad_storage")

    def test_anchor_conflicting_selectors(self):
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "reveal": [0], "reveal_names": ["/x"]},
            "conflicting_selectors")

    def test_anchor_bad_reveal_index(self):
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "reveal": ["nope"]},
            "bad_reveal_index")

    def test_anchor_reveal_blind_rejected(self):
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "reveal": [0], "storage": "blind"},
            "cannot_redact_blind")

    def test_anchor_reveal_with_dry_run_rejected(self):
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "reveal": [0], "dry_run": True},
            "reveal_requires_anchor")

    def test_anchor_no_key_live(self):
        # missing_api_key must fire WITHOUT spawning node — patch env key to None.
        with mock.patch.object(server, "_env_api_key", return_value=None):
            self._assert_no_spawn(server._handle_anchor_disclosable,
                                  {"file_path": str(self.t.json)}, "missing_api_key")

    def test_create_missing_paths(self):
        self._assert_no_spawn(server._handle_create_disclosure, {}, "missing_original_path")
        self._assert_no_spawn(server._handle_create_disclosure,
                              {"original_path": str(self.t.json)}, "missing_source_mbnt_path")

    def test_create_not_a_bundle(self):
        self._assert_no_spawn(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.notzip),
             "reveal": [0]},
            "not_a_bundle")

    def test_create_conflicting_and_missing_reveal(self):
        self._assert_no_spawn(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
             "reveal": [0], "reveal_names": ["/x"]},
            "conflicting_selectors")
        self._assert_no_spawn(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt)},
            "missing_reveal")

    def test_verify_missing_and_not_bundle(self):
        self._assert_no_spawn(server._handle_verify_disclosure, {}, "missing_disclosure_path")
        self._assert_no_spawn(
            server._handle_verify_disclosure,
            {"disclosure_mbnt_path": str(self.t.notzip)}, "not_a_bundle")

    def test_anchor_bad_granularity(self):
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "granularity": "weird"}, "bad_granularity")

    def test_anchor_bad_reveal_names(self):
        # a bare string (not a list) is truthy and would otherwise spawn a live
        # anchor before failing downstream — must reject before any node spawn.
        self._assert_no_spawn(
            server._handle_anchor_disclosable,
            {"file_path": str(self.t.json), "reveal_names": "/x"}, "bad_reveal_names")

    def test_create_bad_render_mode(self):
        self._assert_no_spawn(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
             "reveal": [0], "render_mode": "weird"}, "bad_render_mode")

    def test_create_bad_reveal_names(self):
        self._assert_no_spawn(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
             "reveal_names": [123]}, "bad_reveal_names")


class NodeUnavailableTest(unittest.TestCase):
    """node>=18 absence is fail-closed `node_unavailable` for all three tools."""

    def setUp(self):
        self._dir = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        self.t = _Tmp(self._dir)

    def _assert_node_unavailable(self, handler, args):
        with mock.patch(_PATCH, side_effect=NodeUnavailable("node_unavailable", "no node")):
            result = _run(handler(args, None))
        self.assertTrue(result.isError)
        self.assertEqual(_body(result)["error"], "node_unavailable")

    def test_anchor(self):
        self._assert_node_unavailable(server._handle_anchor_disclosable,
                                      {"file_path": str(self.t.json), "dry_run": True})

    def test_create(self):
        self._assert_node_unavailable(
            server._handle_create_disclosure,
            {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
             "reveal": [0]})

    def test_verify(self):
        self._assert_node_unavailable(server._handle_verify_disclosure,
                                      {"disclosure_mbnt_path": str(self.t.mbnt)})


class ErrorMappingTest(unittest.TestCase):
    def setUp(self):
        self._dir = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        self.t = _Tmp(self._dir)

    def test_redact_binding_error_passes_fail_code(self):
        err = NodeBridgeError("redact_binding_error", "leaf does not bind",
                              error_class="RedactBindingError",
                              fail_code="linked_anchor_canonical_hash_mismatch")
        with mock.patch(_PATCH, side_effect=err):
            result = _run(server._handle_create_disclosure(
                {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
                 "reveal": [0]}, None))
        b = _body(result)
        self.assertTrue(result.isError)
        self.assertEqual(b["error"], "redact_binding_error")
        self.assertEqual(b["fail_code"], "linked_anchor_canonical_hash_mismatch")
        self.assertEqual(b["error_class"], "RedactBindingError")

    def test_bad_disclosure_maps_through(self):
        err = NodeBridgeError("bad_disclosure", "no manifest")
        with mock.patch(_PATCH, side_effect=err):
            result = _run(server._handle_verify_disclosure(
                {"disclosure_mbnt_path": str(self.t.mbnt)}, None))
        self.assertEqual(_body(result)["error"], "bad_disclosure")


class SuccessWiringTest(unittest.TestCase):
    def setUp(self):
        self._dir = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        self.t = _Tmp(self._dir)

    def test_anchor_dry_run_shape_and_op(self):
        ret = {"scheme": "json-ast-v1", "leafCount": 4, "root": "ab" * 32,
               "dryRun": True, "body": {"salt_b64": "[REDACTED]", "mode": "sealed"}}
        with mock.patch(_PATCH, return_value=ret) as m:
            result = _run(server._handle_anchor_disclosable(
                {"file_path": str(self.t.json), "dry_run": True}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertFalse(b["anchored"])
        self.assertTrue(b["dry_run"])
        self.assertEqual(b["scheme"], "json-ast-v1")
        self.assertEqual(b["leaf_count"], 4)
        self.assertEqual(b["preview_body"]["salt_b64"], "[REDACTED]")
        op, params = m.call_args.args[0], m.call_args.args[1]
        self.assertEqual(op, "anchor")
        self.assertTrue(params["dry_run"])
        # dry-run never carries the key
        self.assertIsNone(m.call_args.kwargs["api_key"])

    def test_anchor_live_passes_key_and_canonical_keys(self):
        ret = {"scheme": "json-ast-v1", "leafCount": 4, "root": "a" * 64,
               "txid": "tx123", "proof_id": "pid123",
               "sourceMbntPath": "/tmp/a.source.mbnt", "verify": {"ok": True}}
        with mock.patch.object(server, "_env_api_key", return_value="sk_live"):
            with mock.patch(_PATCH, return_value=ret) as m:
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(self.t.json)}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertTrue(b["anchored"])
        self.assertEqual(b["proof_id"], "pid123")
        self.assertEqual(b["txid"], "tx123")
        self.assertEqual(b["source_mbnt_path"], "/tmp/a.source.mbnt")
        self.assertEqual(m.call_args.kwargs["api_key"], "sk_live")

    def test_anchor_self_verify_failure_is_fatal(self):
        ret = {"scheme": "json-ast-v1", "leafCount": 4, "root": "a" * 64,
               "txid": "tx", "proof_id": "p", "sourceMbntPath": "/x",
               "verify": {"ok": False, "fail_code": "recompute_root_mismatch"}}
        with mock.patch.object(server, "_env_api_key", return_value="sk"):
            with mock.patch(_PATCH, return_value=ret):
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(self.t.json)}, None))
        b = _body(result)
        self.assertTrue(result.isError)
        self.assertEqual(b["error"], "self_verify_failed")
        self.assertEqual(b["fail_code"], "recompute_root_mismatch")

    def test_anchor_one_shot_reveal_runs_create_too(self):
        anchor_ret = {"scheme": "json-ast-v1", "leafCount": 4, "root": "a" * 64,
                      "txid": "tx", "proof_id": "p",
                      "sourceMbntPath": str(self.t.mbnt), "verify": {"ok": True}}
        create_ret = {"redacted_copy_path": "/x.redacted.json",
                      "disclosure_mbnt_path": "/x.disclosure.mbnt",
                      "root": "a" * 64, "revealed_count": 1,
                      "self_verify": {"ok": True}}
        with mock.patch.object(server, "_env_api_key", return_value="sk"):
            with mock.patch(_PATCH, side_effect=[anchor_ret, create_ret]) as m:
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(self.t.json), "reveal": [0], "storage": "mirror"}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertEqual([c.args[0] for c in m.call_args_list], ["anchor", "create"])
        self.assertEqual(b["disclosure"]["disclosure_mbnt_path"], "/x.disclosure.mbnt")
        self.assertEqual(b["disclosure"]["revealed_count"], 1)
        # the create sub-op must NOT receive the API key (local-only)
        self.assertIsNone(m.call_args_list[1].kwargs["api_key"])

    def test_create_list_only_op_and_no_key(self):
        ret = {"scheme": "json-ast-v1", "leaf_count": 3,
               "leaves": [{"index": 0, "selector": "/order_id"}]}
        with mock.patch(_PATCH, return_value=ret) as m:
            result = _run(server._handle_create_disclosure(
                {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
                 "list_only": True}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertEqual(b["leaf_count"], 3)
        self.assertEqual(m.call_args.args[0], "list")
        self.assertIsNone(m.call_args.kwargs["api_key"])  # never keyed

    def test_create_redact_shape(self):
        ret = {"redacted_copy_path": "/r.json", "disclosure_mbnt_path": "/d.mbnt",
               "root": "a" * 64, "revealed_count": 2, "self_verify": {"ok": True}}
        with mock.patch(_PATCH, return_value=ret) as m:
            result = _run(server._handle_create_disclosure(
                {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
                 "reveal_names": ["/order_id", "/amount_usd"]}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertEqual(b["disclosure_mbnt_path"], "/d.mbnt")
        self.assertEqual(b["revealed_count"], 2)
        self.assertEqual(m.call_args.args[0], "create")
        self.assertEqual(m.call_args.args[1]["reveal_names"], ["/order_id", "/amount_usd"])

    def test_verify_true_includes_chain_context(self):
        ret = {"verified": True, "fail_code": None, "scheme": "json-ast-v1",
               "root": "a" * 64, "linked_txid": "tx", "carrier_sha256": "c" * 64,
               "revealed_count": 2, "view_checked": False}
        with mock.patch(_PATCH, return_value=ret) as m:
            result = _run(server._handle_verify_disclosure(
                {"disclosure_mbnt_path": str(self.t.mbnt)}, None))
        b = _body(result)
        self.assertFalse(result.isError)
        self.assertTrue(b["verified"])
        self.assertEqual(b["linked_txid"], "tx")
        self.assertFalse(b["chain_confirmation"]["checked_here"])
        self.assertEqual(m.call_args.args[0], "verify")
        self.assertIsNone(m.call_args.kwargs["api_key"])

    def test_verify_false_is_success_with_reason(self):
        ret = {"verified": False, "fail_code": "leaf_hash_mismatch",
               "scheme": "json-ast-v1", "root": "a" * 64, "linked_txid": "tx",
               "carrier_sha256": "c" * 64}
        with mock.patch(_PATCH, return_value=ret):
            result = _run(server._handle_verify_disclosure(
                {"disclosure_mbnt_path": str(self.t.mbnt)}, None))
        b = _body(result)
        self.assertFalse(result.isError)  # a failed bind is NOT a tool error
        self.assertFalse(b["verified"])
        self.assertEqual(b["reason"], "leaf_hash_mismatch")


class OneShotAndSelfVerifyTest(unittest.TestCase):
    """Behavior once the live anchor has broadcast: a failed (local, re-runnable)
    one-shot disclosure must NOT discard the on-chain anchor result; the
    standalone create path treats a non-binding redaction as fatal."""

    def setUp(self):
        self._dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.t = _Tmp(self._dir)
        self._anchor_ret = {"scheme": "json-ast-v1", "leafCount": 4, "root": "a" * 64,
                            "txid": "tx", "proof_id": "p",
                            "sourceMbntPath": str(self.t.mbnt), "verify": {"ok": True}}

    def test_one_shot_create_failure_keeps_anchor_success(self):
        err = NodeBridgeError("redact_binding_error", "bad selector",
                              error_class="RedactBindingError", fail_code="x")
        with mock.patch.object(server, "_env_api_key", return_value="sk"):
            with mock.patch(_PATCH, side_effect=[self._anchor_ret, err]) as m:
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(self.t.json), "reveal": [0], "storage": "mirror"}, None))
        b = _body(result)
        # anchor already broadcast -> SUCCESS, anchor coords preserved
        self.assertFalse(result.isError)
        self.assertEqual(b["proof_id"], "p")
        self.assertEqual(b["txid"], "tx")
        self.assertEqual(b["source_mbnt_path"], str(self.t.mbnt))
        self.assertEqual(b["disclosure"]["error"], "redact_binding_error")
        self.assertEqual([c.args[0] for c in m.call_args_list], ["anchor", "create"])

    def test_one_shot_self_verify_failure_embedded_not_fatal(self):
        create_ret = {"redacted_copy_path": "/r", "disclosure_mbnt_path": "/d",
                      "root": "a" * 64, "revealed_count": 1,
                      "self_verify": {"ok": False, "fail_code": "leaf_hash_mismatch"}}
        with mock.patch.object(server, "_env_api_key", return_value="sk"):
            with mock.patch(_PATCH, side_effect=[self._anchor_ret, create_ret]):
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(self.t.json), "reveal": [0]}, None))
        b = _body(result)
        self.assertFalse(result.isError)  # anchor is sound
        self.assertEqual(b["proof_id"], "p")
        self.assertEqual(b["disclosure"]["error"], "self_verify_failed")

    def test_standalone_create_self_verify_failure_is_fatal(self):
        ret = {"redacted_copy_path": "/r", "disclosure_mbnt_path": "/d", "root": "a" * 64,
               "revealed_count": 1,
               "self_verify": {"ok": False, "fail_code": "recompute_root_mismatch"}}
        with mock.patch(_PATCH, return_value=ret):
            result = _run(server._handle_create_disclosure(
                {"original_path": str(self.t.json), "source_mbnt_path": str(self.t.mbnt),
                 "reveal": [0]}, None))
        b = _body(result)
        self.assertTrue(result.isError)
        self.assertEqual(b["error"], "self_verify_failed")
        self.assertEqual(b["fail_code"], "recompute_root_mismatch")


@unittest.skipUnless(
    shutil.which("node") or os.environ.get("SATSIGNAL_NODE"),
    "node>=18 not available — disclosable-* end-to-end is skipped",
)
class NodeEndToEndTest(unittest.TestCase):
    """Exercise the REAL vendored Node builder (no mock) on the no-network
    dry-run anchor path: proves the vendored snapshot loads + the sealed
    envelope builds under node, and that the master salt never escapes."""

    def test_dry_run_anchor_through_real_node(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.json"
            p.write_text('{"order_id":"A-100","amount_usd":42.5,"items":[1,2]}')
            # No SATSIGNAL_API_KEY needed (dry_run); explicitly ensure no live
            # anchor is even possible from this test.
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SATSIGNAL_API_KEY", None)
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(p), "dry_run": True}, None))
        b = _body(result)
        self.assertFalse(result.isError, b)
        self.assertEqual(b["scheme"], "json-ast-v1")
        self.assertTrue(b["leaf_count"] >= 1)
        self.assertRegex(b["root"], r"^[0-9a-f]{64}$")
        self.assertEqual(b["preview_body"]["salt_b64"], "[REDACTED]")

    def test_dry_run_anchor_text_tree_through_real_node(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "note.txt"
            p.write_text("Line one.\nLine two.\n")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SATSIGNAL_API_KEY", None)
                result = _run(server._handle_anchor_disclosable(
                    {"file_path": str(p), "dry_run": True}, None))
        b = _body(result)
        self.assertFalse(result.isError, b)
        self.assertEqual(b["scheme"], "text-tree-v1")


if __name__ == "__main__":
    unittest.main()
