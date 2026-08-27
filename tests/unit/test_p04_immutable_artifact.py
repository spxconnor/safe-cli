"""Regression tests for P0 4: immutable artifact binding.

The verified artifact must be bound to its SHA256 so the executor
cannot run something different from what was verified.
"""
import os
import tempfile
import unittest
from pathlib import Path

from bv.artifact import Artifact
from bv.script import from_path


class TestArtifactBinding(unittest.TestCase):

    def test_artifact_from_text(self):
        a = Artifact.from_text("hello\n")
        # SHA256 of "hello\n" (6 bytes)
        self.assertEqual(len(a.sha256), 64)
        self.assertEqual(a.content, b"hello\n")

    def test_artifact_mismatch_raises(self):
        """An Artifact cannot be created with mismatched content and sha."""
        import hashlib
        real_hash = hashlib.sha256(b"good").hexdigest()
        with self.assertRaises(ValueError):
            Artifact(content=b"bad", sha256=real_hash)

    def test_artifact_content_immutable(self):
        a = Artifact.from_text("x")
        with self.assertRaises(Exception):
            # frozen dataclass: assignment raises FrozenInstanceError
            a.content = b"y"


class TestScriptIntegrity(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "test.sh"
        self.path.write_text("#!/usr/bin/env bash\necho ok\n")

    def test_verify_integrity_passes_unchanged(self):
        s = from_path(str(self.path))
        self.assertTrue(s.verify_integrity())

    def test_verify_integrity_fails_after_modification(self):
        s = from_path(str(self.path))
        # The verifier "saw" the original content. Now an attacker
        # (or a confused user) modifies the file.
        self.path.write_text("#!/usr/bin/env bash\nrm -rf $HOME\n")
        self.assertFalse(s.verify_integrity())

    def test_content_sha256_matches(self):
        import hashlib
        s = from_path(str(self.path))
        expected = hashlib.sha256(b"#!/usr/bin/env bash\necho ok\n").hexdigest()
        self.assertEqual(s.content_sha256, expected)


if __name__ == "__main__":
    unittest.main()
