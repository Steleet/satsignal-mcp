"""Tool-handler tests.

httpx is mocked out — these are unit tests of the MCP layer's behavior
(dry-run paths, error mapping, sha computation, response shape), not of
the live Satsignal API.
"""

import asyncio
import hashlib
import json
import tempfile
import unittest
import unittest.mock as mock
import zipfile
from pathlib import Path

from satsignal_mcp.api import AnchorResult, ApiError
from satsignal_mcp.server import (
    _handle_anchor_file,
    _handle_anchor_json,
    _handle_anchor_text,
    _handle_lookup_hash,
    _handle_verify_bundle,
    _tool_definitions,
)


def _run(coro):
    return asyncio.run(coro)


def _parse(response_list) -> dict:
    """Helper: pull the JSON payload out of a TextContent response."""
    assert len(response_list) == 1
    return json.loads(response_list[0].text)


def _stub_anchor_result(*, sha: str, matter: str = "inbox",
                        duplicate: bool = False) -> AnchorResult:
    return AnchorResult(
        bundle_id="bundle_test_001",
        txid="t" * 64,
        mode="standard",
        matter_slug=matter,
        receipt_url=f"https://example.com/w/ws/m/{matter}/r/bundle_test_001",
        bundle_url="https://example.com/bundle/bundle_test_001.mbnt",
        duplicate=duplicate,
        raw={},
    )


class AnchorFileDryRunTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "doc.txt"
        self.path.write_bytes(b"hello world")
        self.expected_sha = hashlib.sha256(b"hello world").hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_computes_sha_without_calling_api(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_file(
            {"path": str(self.path), "dry_run": True}, api,
        ))
        payload = _parse(result)
        self.assertFalse(payload["anchored"])
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["sha256_hex"], self.expected_sha)
        self.assertEqual(payload["file_size"], 11)
        self.assertEqual(payload["filename"], "doc.txt")
        api.anchor_standard.assert_not_called()

    def test_real_anchor_passes_correct_payload(self):
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(
            sha=self.expected_sha,
        )
        result = _run(_handle_anchor_file(
            {"path": str(self.path), "matter": "case42",
             "label": "evidence A"}, api,
        ))
        payload = _parse(result)
        self.assertTrue(payload["anchored"])
        self.assertEqual(payload["sha256_hex"], self.expected_sha)
        self.assertEqual(payload["bundle_id"], "bundle_test_001")
        api.anchor_standard.assert_called_once_with(
            matter_slug="case42",
            sha256_hex=self.expected_sha,
            file_size=11,
            label="evidence A",
            filename="doc.txt",
            force_new=False,
        )

    def test_missing_path_returns_error(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_file({}, api))
        payload = _parse(result)
        self.assertEqual(payload["error"], "missing_path")
        api.anchor_standard.assert_not_called()

    def test_nonexistent_path_returns_error(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_file(
            {"path": "/no/such/file.txt"}, api,
        ))
        payload = _parse(result)
        self.assertEqual(payload["error"], "not_a_file")
        api.anchor_standard.assert_not_called()

    def test_api_error_surfaces_code_and_status(self):
        api = mock.AsyncMock()
        api.anchor_standard.side_effect = ApiError(
            401, "missing_api_key", "set SATSIGNAL_API_KEY",
        )
        result = _run(_handle_anchor_file({"path": str(self.path)}, api))
        payload = _parse(result)
        self.assertEqual(payload["error"], "missing_api_key")
        self.assertEqual(payload["status"], 401)


class AnchorTextTest(unittest.TestCase):

    def test_dry_run_sha_matches_utf8_bytes(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_text(
            {"text": "café", "dry_run": True}, api,
        ))
        payload = _parse(result)
        self.assertEqual(
            payload["sha256_hex"],
            hashlib.sha256("café".encode("utf-8")).hexdigest(),
        )
        self.assertEqual(payload["byte_length"], len("café".encode("utf-8")))
        api.anchor_standard.assert_not_called()

    def test_real_anchor_sends_correct_size(self):
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(sha="a" * 64)
        _run(_handle_anchor_text({"text": "hello"}, api))
        kwargs = api.anchor_standard.call_args.kwargs
        self.assertEqual(kwargs["file_size"], 5)
        self.assertEqual(
            kwargs["sha256_hex"],
            hashlib.sha256(b"hello").hexdigest(),
        )
        self.assertNotIn("filename", kwargs)


class AnchorJsonTest(unittest.TestCase):

    def test_dry_run_returns_canonical_bytes(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": {"b": 1, "a": 2}, "dry_run": True}, api,
        ))
        payload = _parse(result)
        # Sorted keys: a before b.
        self.assertEqual(payload["canonical_bytes"], '{"a":2,"b":1}')
        self.assertEqual(payload["byte_length"], 13)
        api.anchor_standard.assert_not_called()

    def test_real_anchor_includes_canonical_bytes_in_response(self):
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(sha="a" * 64)
        result = _run(_handle_anchor_json(
            {"data": {"hello": "world"}}, api,
        ))
        payload = _parse(result)
        self.assertEqual(payload["canonical_bytes"], '{"hello":"world"}')
        self.assertTrue(payload["anchored"])

    def test_non_finite_float_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": {"x": float("nan")}}, api,
        ))
        payload = _parse(result)
        self.assertEqual(payload["error"], "canonicalization_failed")
        api.anchor_standard.assert_not_called()

    def test_missing_data_returns_error(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json({}, api))
        payload = _parse(result)
        self.assertEqual(payload["error"], "missing_data")


class LookupHashTest(unittest.TestCase):

    def test_hit_maps_to_hit_true(self):
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {
            "bundle_id": "b1", "txid": "t" * 64,
            "created_utc": "2026-05-14T00:00:00Z",
        }
        result = _run(_handle_lookup_hash(
            {"sha256_hex": "a" * 64}, api,
        ))
        payload = _parse(result)
        self.assertTrue(payload["hit"])
        self.assertEqual(payload["bundle_id"], "b1")
        self.assertEqual(payload["txid"], "t" * 64)

    def test_miss_maps_to_hit_false(self):
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {
            "miss": True, "reason": "sha_not_indexed_as_file_hash",
        }
        result = _run(_handle_lookup_hash(
            {"sha256_hex": "a" * 64}, api,
        ))
        payload = _parse(result)
        self.assertFalse(payload["hit"])
        self.assertEqual(payload["reason"], "sha_not_indexed_as_file_hash")


class VerifyBundleTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.tmp.name) / "test.mbnt"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_bundle(self, manifest: dict, canonical: dict | None = None
                       ) -> None:
        if canonical is None:
            # Default canonical has the document_sha256 verify_bundle
            # actually reads (manifest only carries the 40-hex
            # doc_hash_expected; the 64-hex file sha lives in canonical).
            canonical = {"subject": {"document_sha256": "a" * 64}}
        with zipfile.ZipFile(self.bundle, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("canonical.json", json.dumps(canonical))

    def test_verified_true_when_txid_matches(self):
        self._write_bundle({"txid": "t" * 64})
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {
            "bundle_id": "b1", "txid": "t" * 64, "created_utc": "x",
        }
        result = _run(_handle_verify_bundle({"path": str(self.bundle)}, api))
        payload = _parse(result)
        self.assertTrue(payload["verified"])

    def test_verified_false_on_txid_mismatch(self):
        """Locally-fabricated bundle: real sha in canonical but bogus
        claimed txid in manifest. Must report verified=false with
        txid_mismatch."""
        self._write_bundle({"txid": "f" * 64})  # forged
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {
            "bundle_id": "b1", "txid": "t" * 64,  # real
            "created_utc": "x",
        }
        result = _run(_handle_verify_bundle({"path": str(self.bundle)}, api))
        payload = _parse(result)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload["reason"], "txid_mismatch")

    def test_verified_false_on_lookup_miss(self):
        self._write_bundle({"txid": "t" * 64})
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {"miss": True, "reason": "x"}
        result = _run(_handle_verify_bundle({"path": str(self.bundle)}, api))
        payload = _parse(result)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload["reason"], "sha_not_indexed")

    def test_sealed_bundle_no_document_sha_returns_error(self):
        """Sealed/manifest bundles don't put document_sha256 in
        canonical.subject; verify should explain rather than silently
        fail (or worse, lookup the wrong field and false-miss)."""
        self._write_bundle(
            {"mode": "sealed", "txid": "t" * 64},
            canonical={"subject": {"byte_exact_commitment": "c" * 64}},
        )
        api = mock.AsyncMock()
        result = _run(_handle_verify_bundle({"path": str(self.bundle)}, api))
        payload = _parse(result)
        self.assertEqual(payload["error"], "no_file_sha")
        self.assertEqual(payload["manifest_mode"], "sealed")
        api.lookup_hash.assert_not_called()

    def test_lookup_called_with_canonical_sha_not_manifest_hash(self):
        """Regression: pre-fix the handler read manifest.doc_hash_expected
        (40-hex truncated). The real file sha (64-hex) is in
        canonical.subject.document_sha256, and that's what lookup_hash
        indexes. Confirm we pass the canonical one."""
        self._write_bundle(
            {
                "txid": "t" * 64,
                "doc_hash_expected": "ab" * 20,  # 40-hex; must NOT be sent
            },
            canonical={"subject": {"document_sha256": "9" * 64}},
        )
        api = mock.AsyncMock()
        api.lookup_hash.return_value = {
            "bundle_id": "b1", "txid": "t" * 64, "created_utc": "x",
        }
        _run(_handle_verify_bundle({"path": str(self.bundle)}, api))
        api.lookup_hash.assert_called_once_with("9" * 64)


class ToolDefinitionTest(unittest.TestCase):

    def test_five_tools_declared(self):
        tools = _tool_definitions()
        self.assertEqual(
            [t.name for t in tools],
            ["anchor_file", "anchor_text", "anchor_json",
             "lookup_hash", "verify_bundle"],
        )

    def test_anchor_tools_have_dry_run_with_default_false(self):
        for tool in _tool_definitions():
            if not tool.name.startswith("anchor_"):
                continue
            props = tool.inputSchema["properties"]
            self.assertIn("dry_run", props)
            self.assertFalse(props["dry_run"]["default"])


if __name__ == "__main__":
    unittest.main()
