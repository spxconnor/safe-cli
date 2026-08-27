"""Regression tests for the P1 fixes in this round."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/safe-cli-repo")

from bv.cache.verify_cache import cache_key, environment_snapshot, environment_fingerprint
from bv.config import load_config


class TestP119StrongerCacheKeys(unittest.TestCase):
    """P1-19: the cache key must include tool versions, safe-cli
    version, Python version, and a config hash. Without those,
    results from old tool / config versions can be silently reused."""

    def test_environment_snapshot_has_required_fields(self):
        snap = environment_snapshot()
        self.assertIn("safe_cli_version", snap)
        self.assertIn("shellcheck_version", snap)
        self.assertIn("shfmt_version", snap)
        self.assertIn("bats_version", snap)
        self.assertIn("python_version", snap)
        self.assertIn("sandbox_image", snap)

    def test_environment_fingerprint_is_stable(self):
        """Calling twice in a row should produce the same fingerprint
        (no nondeterminism in the snapshot)."""
        a = environment_fingerprint()
        b = environment_fingerprint()
        self.assertEqual(a, b)

    def test_cache_key_differs_when_shellcheck_version_differs(self):
        """If shellcheck_version were to change, the cache key would
        change too. We test this by passing a fake config and
        monkey-patching the snapshot."""
        import bv.cache.verify_cache as mod
        original = mod.environment_snapshot

        def fake_v1(cfg=None):
            snap = original(cfg)
            snap["shellcheck_version"] = "v1"
            return snap

        def fake_v2(cfg=None):
            snap = original(cfg)
            snap["shellcheck_version"] = "v2"
            return snap

        mod.environment_snapshot = fake_v1
        try:
            k1 = cache_key("script content", load_config(), "shellcheck")
        finally:
            mod.environment_snapshot = original
        mod.environment_snapshot = fake_v2
        try:
            k2 = cache_key("script content", load_config(), "shellcheck")
        finally:
            mod.environment_snapshot = original
        self.assertNotEqual(k1, k2)
