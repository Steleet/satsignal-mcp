"""Tests for the JSON canonicalization helper.

The canonical bytes are what the on-chain sha256 commits to; if these
ever drift, every previously-anchored receipt becomes unverifiable.
Pin the exact bytes for representative shapes.
"""

import unittest

from satsignal_mcp.canonical import (
    CanonicalizationError, canonicalize, sha256_hex,
)


class CanonicalizeTest(unittest.TestCase):

    def test_dict_keys_are_sorted(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": 2}),
            b'{"a":2,"b":1}',
        )

    def test_nested_objects_sorted_recursively(self):
        self.assertEqual(
            canonicalize({"outer": {"z": 1, "a": 2}, "list": [3, 1, 2]}),
            b'{"list":[3,1,2],"outer":{"a":2,"z":1}}',
        )

    def test_separators_are_compact(self):
        # No whitespace around colons or commas — pins byte-for-byte
        # reproducibility across stdlib implementations.
        self.assertEqual(
            canonicalize([1, 2, {"k": "v"}]),
            b'[1,2,{"k":"v"}]',
        )

    def test_unicode_preserved_not_escaped(self):
        # ensure_ascii=False so a "café" payload doesn't sha differently
        # depending on whether the JSON encoder escapes the é.
        self.assertEqual(
            canonicalize({"name": "café"}),
            '{"name":"café"}'.encode("utf-8"),
        )

    def test_null_bool_int_float(self):
        self.assertEqual(
            canonicalize({"n": None, "t": True, "f": False, "i": 0, "x": 1.5}),
            b'{"f":false,"i":0,"n":null,"t":true,"x":1.5}',
        )

    def test_rejects_nan(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"x": float("nan")})

    def test_rejects_infinity(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"x": float("inf")})
        with self.assertRaises(CanonicalizationError):
            canonicalize({"x": float("-inf")})

    def test_rejects_non_string_dict_keys(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({1: "v"})

    def test_sha256_hex_is_64_lowercase(self):
        digest = sha256_hex(canonicalize({"hello": "world"}))
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        # Pin the digest so any future change to canonicalization is
        # caught by a failing assertion, not by silent breakage of every
        # previously-anchored receipt.
        self.assertEqual(
            digest,
            "93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588",
        )


class CanonicalJCSConformanceTest(unittest.TestCase):
    """v0.5.0: canonicalize() implements full RFC 8785 JCS — NFC
    normalize string values + dict keys, sort dict keys by UTF-16-BE
    byte order. Previous impl (`json.dumps(sort_keys=True, …)`)
    agreed with JCS by accident for ASCII-only payloads but diverged
    on any multibyte unicode, breaking cross-tool verification
    against satsignal-cli (which has been authoritative all along).
    """

    def test_ascii_only_matches_old_behavior(self):
        """ASCII-only canonical bytes are byte-identical to the
        pre-0.5 `json.dumps(sort_keys=True, separators=(',',':'),
        ensure_ascii=False)` output. No-regression guard for the
        common path — every previously-anchored ASCII bundle stays
        verifiable."""
        data = {
            "b": 1,
            "a": [1, 2, 3],
            "c": {"y": "hello", "x": "world"},
            "n": None,
            "t": True,
        }
        import json as _json
        old_impl = _json.dumps(
            data, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(canonicalize(data), old_impl)

    def test_nfc_normalization_on_string_values(self):
        """RFC 8785 §3.2.5: strings are NFC-normalized before
        serialization. 'café' with the composed é (U+00E9, 1 code
        point) and the decomposed e+◌́ (U+0065 U+0301, 2 code points)
        MUST produce identical canonical bytes — otherwise two LLM
        callers emitting visually-identical text get different sha256
        hashes and cross-anchor verification fails."""
        composed = canonicalize({"k": "café"})
        decomposed = canonicalize({"k": "café"})
        self.assertEqual(composed, decomposed)
        # And the canonical form is NFC (composed).
        self.assertIn("café".encode("utf-8"), composed)

    def test_nfc_normalization_on_dict_keys(self):
        """Same rule applies to dict keys, not just values."""
        composed = canonicalize({"café": 1})
        decomposed = canonicalize({"café": 1})
        self.assertEqual(composed, decomposed)

    def test_utf16_be_key_sort_not_lexicographic(self):
        """RFC 8785 §3.2.3: dict keys sort by UTF-16-BE byte order,
        NOT codepoint / lexicographic order. For BMP characters the
        two orders agree; for supplementary-plane characters (above
        U+FFFF) they DISAGREE because UTF-16 encodes those as
        surrogate pairs starting with 0xD8… (which sorts BEFORE many
        BMP characters in UTF-16-BE byte order, but AFTER them in
        codepoint order).

        Pick a BMP key ("z", U+007A → 0x00 0x7A in UTF-16-BE) and a
        supplementary-plane key (😀, U+1F600 → 0xD83D 0xDE00 in
        UTF-16-BE). Codepoint sort: "z" < "😀" (U+7A < U+1F600).
        UTF-16-BE byte sort: "😀" < "z" (0xD8 < 0x00 is false…
        actually 0x00 < 0xD8, so "z" still sorts first by the leading
        byte; the byte orders DO agree here). Use a less-trivial
        example.

        Easier: NFC normalization changes the key. "Å" decomposed
        (U+0041 U+030A) starts with "A" (0x41) in UTF-16-BE; NFC-
        normalized it becomes U+00C5 → 0x00 0xC5. Compared to "B"
        (U+0042 → 0x00 0x42): "B" < "Å" after NFC (0x42 < 0xC5).
        Without NFC (raw decomposed form): "A" + combining starts
        with 0x41, which sorts BEFORE "B" (0x42). Different order →
        different bytes.

        We pin the JCS-conformant order (NFC-then-sort) here.
        """
        data = {"B": 1, "Å": 2}  # decomposed Å
        out = canonicalize(data)
        # JCS: NFC-normalize keys first ("Å" -> "Å"),
        # then sort by UTF-16-BE bytes. "B" (0x00 0x42) sorts BEFORE
        # "Å" (0x00 0xc5).
        self.assertEqual(
            out,
            '{"B":1,"Å":2}'.encode("utf-8"),
        )

    def test_multibyte_value_canonical(self):
        """Surrogate-pair value (😀, U+1F600) round-trips through JCS
        as the UTF-8 bytes for the codepoint, no escape (ensure_ascii
        is False)."""
        out = canonicalize({"k": "\U0001f600"})
        self.assertEqual(out, '{"k":"\U0001f600"}'.encode("utf-8"))

    def test_pinned_sha_for_known_ascii_payload_unchanged(self):
        """The pinned sha256 from the pre-0.5 era (test_sha256_hex_is
        _64_lowercase) is for {'hello': 'world'} — pure ASCII, so
        canonical bytes must NOT have changed. Cross-checks that the
        no-regression contract holds for the most common shape."""
        digest = sha256_hex(canonicalize({"hello": "world"}))
        self.assertEqual(
            digest,
            "93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588",
        )

    def test_cross_tool_match_with_satsignal_cli_jcs(self):
        """Direct cross-validation against satsignal-cli's _jcs (the
        authoritative impl). For unicode payloads both libs MUST
        produce byte-identical canonical bytes — that's the entire
        point of the v0.5 fix."""
        try:
            from satsignal.verify import _jcs
        except ImportError:
            self.skipTest("satsignal-cli not installed")
        cases = [
            {"hello": "world"},
            {"café": "café"},
            {"café": "café"},        # decomposed -> NFC
            {"B": 1, "Å": 2},              # key sort + NFC
            {"emoji": "\U0001f600"},              # surrogate pair
            [1, 2, {"nested": "é"}],
        ]
        for data in cases:
            self.assertEqual(
                canonicalize(data),
                _jcs(data),
                f"JCS mismatch for {data!r}",
            )


if __name__ == "__main__":
    unittest.main()
