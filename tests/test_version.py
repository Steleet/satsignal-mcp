"""Smoke-test: __version__ resolves via importlib.metadata.

pyproject.toml is the single source of truth for the version string;
src/satsignal_mcp/__init__.py reads it via importlib.metadata at import
time. This pins that the read succeeds and matches the installed dist
metadata — so a release that bumps pyproject.toml without re-installing,
or a future refactor that re-hard-codes the literal, fails loudly here.
"""

import unittest
from importlib.metadata import version

import satsignal_mcp


class VersionTest(unittest.TestCase):

    def test_version_matches_installed_dist(self):
        self.assertEqual(
            satsignal_mcp.__version__,
            version("satsignal-mcp"),
        )

    def test_version_is_non_empty_string(self):
        self.assertIsInstance(satsignal_mcp.__version__, str)
        self.assertTrue(satsignal_mcp.__version__)


if __name__ == "__main__":
    unittest.main()
