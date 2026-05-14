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


if __name__ == "__main__":
    unittest.main()
