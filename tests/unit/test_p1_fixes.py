import os
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


class TestP118PathSnapshot(unittest.TestCase):
    """P1-18: TOCTOU defense. The Script captures a path snapshot
    at load time and can verify it has not been swapped before
    execution (e.g. via symlink replacement)."""

    def test_path_snapshot_captures_inode_and_dev(self):
        import tempfile
        from bv.script import from_path
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tf:
            tf.write("#!/usr/bin/env bash\necho ok\n")
            path = tf.name
        try:
            s = from_path(path)
            snap = s.path_snapshot()
            self.assertTrue(snap.get("exists"))
            self.assertGreater(snap.get("inode", 0), 0)
            self.assertGreater(snap.get("size", 0), 0)
            self.assertEqual(len(snap.get("sha256", "")), 64)
        finally:
            os.unlink(path)

    def test_verify_unchanged_since_detects_modification(self):
        import tempfile
        from bv.script import from_path
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tf:
            tf.write("#!/usr/bin/env bash\necho v1\n")
            path = tf.name
        try:
            s = from_path(path)
            snap = s.path_snapshot()
            # Modify the file in place (TOCTOU attack simulation)
            with open(path, "w") as f:
                f.write("#!/usr/bin/env bash\necho v2\n")
            self.assertFalse(s.verify_unchanged_since(snap))
        finally:
            os.unlink(path)
