"""Tests for the Node subprocess bridge (node_bridge.py).

These never spawn a real node process — subprocess.run is mocked — so they
run anywhere, including boxes with no node installed. The end-to-end
node-required path is exercised separately in test_disclosable_tools.py under
@skipUnless(node present).
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from satsignal_mcp import node_bridge


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["node", "cli.mjs"],
        returncode=returncode,
        stdout=stdout.encode("utf-8") if isinstance(stdout, str) else stdout,
        stderr=stderr.encode("utf-8") if isinstance(stderr, str) else stderr,
    )


class FindNodeTest(unittest.TestCase):
    def test_falls_back_to_path_node(self):
        with mock.patch.dict("os.environ", {}, clear=False) as _env:
            node_bridge.os.environ.pop("SATSIGNAL_NODE", None)
            with mock.patch.object(node_bridge.shutil, "which",
                                   return_value="/usr/bin/node") as which:
                self.assertEqual(node_bridge.find_node(), "/usr/bin/node")
                which.assert_called_with("node")

    def test_none_when_absent(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            node_bridge.os.environ.pop("SATSIGNAL_NODE", None)
            with mock.patch.object(node_bridge.shutil, "which",
                                   return_value=None):
                self.assertIsNone(node_bridge.find_node())

    def test_override_name_resolved_via_path(self):
        with mock.patch.dict("os.environ", {"SATSIGNAL_NODE": "node22"}):
            with mock.patch.object(node_bridge.shutil, "which",
                                   return_value="/opt/node22/bin/node") as which:
                self.assertEqual(node_bridge.find_node(), "/opt/node22/bin/node")
                which.assert_called_with("node22")

    def test_override_absolute_path_accepted(self):
        with tempfile.NamedTemporaryFile(suffix="-node") as tf:
            Path(tf.name).chmod(0o755)
            with mock.patch.dict("os.environ", {"SATSIGNAL_NODE": tf.name}):
                with mock.patch.object(node_bridge.shutil, "which",
                                       return_value=None):
                    self.assertEqual(node_bridge.find_node(), tf.name)


class RunDisclosureOpTest(unittest.TestCase):
    def setUp(self):
        # A real temp file standing in for the vendored entrypoint, so the
        # _CLI_PATH.is_file() guard passes without a real vendored snapshot.
        self._tmp = tempfile.NamedTemporaryFile(suffix=".mjs", delete=False)
        self._tmp.write(b"// stub\n")
        self._tmp.close()
        self._cli_patch = mock.patch.object(
            node_bridge, "_CLI_PATH", Path(self._tmp.name))
        self._cli_patch.start()
        self._find_patch = mock.patch.object(
            node_bridge, "find_node", return_value="/usr/bin/node")
        self._find_patch.start()

    def tearDown(self):
        self._cli_patch.stop()
        self._find_patch.stop()
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_success_returns_parsed_payload(self):
        payload = {"ok": True, "scheme": "json-ast-v1", "root": "ab" * 32}
        with mock.patch.object(node_bridge.subprocess, "run",
                               return_value=_completed(json.dumps(payload))):
            out = node_bridge.run_disclosure_op("anchor", {"file_path": "/x"},
                                                api_key="sk_live")
        self.assertEqual(out["scheme"], "json-ast-v1")
        self.assertTrue(out["ok"])

    def test_ok_false_raises_with_fail_code(self):
        body = {
            "ok": False,
            "error_code": "redact_binding_error",
            "error_class": "RedactBindingError",
            "fail_code": "linked_anchor_canonical_hash_mismatch",
            "message": "leaf does not bind",
        }
        with mock.patch.object(node_bridge.subprocess, "run",
                               return_value=_completed(json.dumps(body),
                                                       returncode=1)):
            with self.assertRaises(node_bridge.NodeBridgeError) as ctx:
                node_bridge.run_disclosure_op("create", {"a": 1})
        err = ctx.exception
        self.assertEqual(err.code, "redact_binding_error")
        self.assertEqual(err.error_class, "RedactBindingError")
        self.assertEqual(err.fail_code, "linked_anchor_canonical_hash_mismatch")

    def test_non_json_stdout_is_bridge_failure(self):
        with mock.patch.object(node_bridge.subprocess, "run",
                               return_value=_completed("Traceback boom",
                                                       stderr="SyntaxError",
                                                       returncode=1)):
            with self.assertRaises(node_bridge.NodeBridgeError) as ctx:
                node_bridge.run_disclosure_op("verify", {})
        self.assertEqual(ctx.exception.code, "node_bridge_failed")

    def test_timeout_maps_to_node_timeout(self):
        with mock.patch.object(node_bridge.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("node", 1)):
            with self.assertRaises(node_bridge.NodeBridgeError) as ctx:
                node_bridge.run_disclosure_op("verify", {})
        self.assertEqual(ctx.exception.code, "node_timeout")

    def test_node_unavailable_when_no_node(self):
        with mock.patch.object(node_bridge, "find_node", return_value=None):
            with self.assertRaises(node_bridge.NodeUnavailable) as ctx:
                node_bridge.run_disclosure_op("verify", {})
        self.assertEqual(ctx.exception.code, "node_unavailable")

    def test_api_key_reaches_anchor_only(self):
        """SECURITY: the bearer token is exposed to op='anchor' only; verify /
        create / list must never receive it, even if it sits in the parent env."""
        captured = {}

        def _capture(argv, **kw):
            captured["env"] = kw.get("env", {})
            return _completed(json.dumps({"ok": True}))

        with mock.patch.dict("os.environ", {"SATSIGNAL_API_KEY": "parent_key"}):
            with mock.patch.object(node_bridge.subprocess, "run",
                                   side_effect=_capture):
                node_bridge.run_disclosure_op("anchor", {}, api_key="sk_anchor")
                self.assertEqual(captured["env"].get("SATSIGNAL_API_KEY"),
                                 "sk_anchor")

                for op in ("verify", "create", "list"):
                    node_bridge.run_disclosure_op(op, {}, api_key="sk_anchor")
                    self.assertNotIn("SATSIGNAL_API_KEY", captured["env"],
                                     f"key leaked to op={op}")

    def test_shell_false_and_fixed_argv(self):
        """No shell; argv is exactly [node, cli] so a crafted path can't inject."""
        captured = {}

        def _capture(argv, **kw):
            captured["argv"] = argv
            captured["shell"] = kw.get("shell", False)
            return _completed(json.dumps({"ok": True}))

        with mock.patch.object(node_bridge.subprocess, "run",
                               side_effect=_capture):
            node_bridge.run_disclosure_op("verify", {"disclosure_mbnt_path": "/x"})
        self.assertEqual(captured["argv"][0], "/usr/bin/node")
        self.assertFalse(captured["shell"])


if __name__ == "__main__":
    unittest.main()
