"""Tests for the anchor_json string-coercion guard (H#16).

The 2026-05-22 cold-start probe showed that some MCP hosts (notably
Claude Desktop in certain configs) string-coerce structured tool
arguments at transport time. Pre-0.5.2 `anchor_json` would then
canonicalize the JSON-encoded *string* (escaped-quoted form), producing
a different sha than what the calling agent intended — and silently
anchor those wrong bytes on-chain. v0.5.2 fail-closes that path with
`code="string_coerced_data"`, BEFORE any network call.

Strings that parse to a JSON string (i.e. the caller really did mean
to anchor a string payload) and strings that don't parse at all keep
their pre-0.5.2 behavior and flow through canonicalize.
"""

import asyncio
import json
import unittest
import unittest.mock as mock

from satsignal_mcp.api import AnchorResult
from satsignal_mcp.canonical import canonicalize, sha256_hex
from satsignal_mcp.server import _handle_anchor_json, _tool_definitions


def _run(coro):
    return asyncio.run(coro)


def _parse(response) -> dict:
    content = response.content if hasattr(response, "content") else response
    assert len(content) == 1
    return json.loads(content[0].text)


def _stub_anchor_result(*, sha: str, folder: str = "inbox") -> AnchorResult:
    return AnchorResult(
        proof_id="bundle_test_001",
        txid="t" * 64,
        mode="standard",
        folder_slug=folder,
        proof_url=f"https://example.com/w/ws/m/{folder}/r/bundle_test_001",
        bundle_url="https://example.com/bundle/bundle_test_001.mbnt",
        duplicate=False,
        raw={},
    )


class AnchorJsonStringCoercionGuardTest(unittest.TestCase):
    """The H#16 guard: structured value sent as its JSON-encoded string
    form must fail loudly with `string_coerced_data`, no network call."""

    def test_string_that_parses_as_object_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": '{"k":"v"}'}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        self.assertEqual(payload["parsed_json_type"], "dict")
        self.assertIn("string-coerc", payload["message"])
        api.anchor_standard.assert_not_called()

    def test_string_that_parses_as_array_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": "[1,2,3]"}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        self.assertEqual(payload["parsed_json_type"], "list")
        api.anchor_standard.assert_not_called()

    def test_string_that_parses_as_number_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": "42"}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        self.assertEqual(payload["parsed_json_type"], "int")
        api.anchor_standard.assert_not_called()

    def test_string_that_parses_as_bool_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": "true"}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        self.assertEqual(payload["parsed_json_type"], "bool")
        api.anchor_standard.assert_not_called()

    def test_string_that_parses_as_null_rejected(self):
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": "null"}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        self.assertEqual(payload["parsed_json_type"], "NoneType")
        api.anchor_standard.assert_not_called()

    def test_guard_fires_before_network_in_real_anchor_mode(self):
        """Even with no dry_run, the bug path must not broadcast: the
        on-chain spend (and resulting wrong-sha receipt) was the whole
        symptom that produced this finding."""
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(sha="a" * 64)
        result = _run(_handle_anchor_json(
            {"data": '{"hello":"world"}'}, api,  # NB: not dry_run
        ))
        self.assertTrue(result.isError)
        api.anchor_standard.assert_not_called()


class AnchorJsonGuardFallthroughTest(unittest.TestCase):
    """Strings that the caller actually meant must keep working."""

    def test_string_that_parses_as_string_passes_through(self):
        """`json.loads('"hello"')` returns the string `'hello'`. The
        caller may well have meant to anchor a JSON-string payload; the
        guard must let it through and canonicalize as before."""
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(sha="a" * 64)
        result = _run(_handle_anchor_json(
            {"data": '"hello"'}, api,
        ))
        self.assertFalse(result.isError)
        payload = _parse(result)
        # canonicalize('"hello"') runs the JSON-string-of-a-string through
        # JCS — outer quotes are stripped during normalization in the
        # caller's intent? No: the caller passed a Python str. The MCP
        # layer treats `data` as a Python value, so a Python str (no
        # matter what it parses to) gets canonicalized as a JSON string.
        # What we care about here is: no error, no network short-circuit.
        self.assertTrue(payload["anchored"])

    def test_bare_string_unparseable_passes_through(self):
        """`json.loads('not json {')` raises; the guard must catch the
        ValueError and fall through to canonicalize the original bytes."""
        api = mock.AsyncMock()
        api.anchor_standard.return_value = _stub_anchor_result(sha="a" * 64)
        result = _run(_handle_anchor_json(
            {"data": "not json {"}, api,
        ))
        self.assertFalse(result.isError)
        payload = _parse(result)
        self.assertTrue(payload["anchored"])

    def test_structured_dict_unchanged_behavior(self):
        """The non-coerced happy path: agent sends a real Python dict,
        canonicalize runs, sha is the canonical-bytes sha, the response
        is the same shape as pre-0.5.2."""
        api = mock.AsyncMock()
        expected_canonical = canonicalize({"k": "v"})
        expected_sha = sha256_hex(expected_canonical)
        api.anchor_standard.return_value = _stub_anchor_result(sha=expected_sha)
        result = _run(_handle_anchor_json(
            {"data": {"k": "v"}}, api,
        ))
        self.assertFalse(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["sha256_hex"], expected_sha)
        self.assertEqual(payload["canonical_bytes"], '{"k":"v"}')
        self.assertTrue(payload["anchored"])

    def test_structured_list_unchanged_behavior(self):
        api = mock.AsyncMock()
        expected_canonical = canonicalize([1, 2, 3])
        expected_sha = sha256_hex(expected_canonical)
        api.anchor_standard.return_value = _stub_anchor_result(sha=expected_sha)
        result = _run(_handle_anchor_json(
            {"data": [1, 2, 3]}, api,
        ))
        self.assertFalse(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["sha256_hex"], expected_sha)
        self.assertEqual(payload["canonical_bytes"], "[1,2,3]")

    def test_guard_fires_before_dry_run_too(self):
        """Even on dry_run, the guard must reject — otherwise the agent
        sees a dry-run preview of the *wrong* sha (the escaped-string
        canonical) and gets a false confidence signal."""
        api = mock.AsyncMock()
        result = _run(_handle_anchor_json(
            {"data": '{"k":"v"}', "dry_run": True}, api,
        ))
        self.assertTrue(result.isError)
        payload = _parse(result)
        self.assertEqual(payload["error"], "string_coerced_data")
        api.anchor_standard.assert_not_called()


class AnchorJsonInputSchemaTypeTest(unittest.TestCase):
    """The schema's `data` property must declare a JSON Schema `type`
    that covers all valid JSON values. Pre-0.5.2 it omitted `type`
    entirely, which let non-spec-validating hosts string-coerce the
    structured input silently."""

    def test_data_property_declares_full_json_type_union(self):
        tools = {t.name: t for t in _tool_definitions()}
        data_schema = tools["anchor_json"].inputSchema["properties"]["data"]
        self.assertIn("type", data_schema)
        # JSON Schema "any JSON value" — list-of-types form. Order
        # within the list isn't semantically meaningful, but require all
        # seven JSON value types are present.
        self.assertEqual(
            set(data_schema["type"]),
            {"object", "array", "string", "number", "boolean", "null"},
        )

    def test_data_property_keeps_existing_description(self):
        """Description verbatim from pre-0.5.2 — schemas in cached host
        tool listings would otherwise force a relist."""
        tools = {t.name: t for t in _tool_definitions()}
        data_schema = tools["anchor_json"].inputSchema["properties"]["data"]
        self.assertIn("Any JSON value", data_schema["description"])
        self.assertIn("NaN / Infinity", data_schema["description"])


if __name__ == "__main__":
    unittest.main()
