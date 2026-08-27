"""Regression test for the fuzzer SyntaxWarning fix.

The original bv/quoting/fuzzer.py had a regular triple-quoted docstring
containing a literal backslash-backtick sequence. Python 3.10+ warns
about invalid escape sequences in non-raw strings:

    SyntaxWarning: invalid escape sequence

The fix uses a raw triple-quoted string (starting with the letter 'r'
followed by three double quotes) so the backslash is literal, not
interpreted as an escape.

This test imports the module under warnings-as-errors and verifies no
SyntaxWarning is emitted.
"""
from __future__ import annotations

import sys
import unittest
import warnings

sys.path.insert(0, "/opt/safe-cli-repo")


class TestFuzzerNoSyntaxWarning(unittest.TestCase):
    def test_importing_fuzzer_does_not_warn_about_invalid_escape(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            # Force a fresh import under our warnings filter.
            sys.modules.pop("bv.quoting.fuzzer", None)
            import bv.quoting.fuzzer  # noqa: F401
        syntax_warnings = [
            w for w in caught
            if issubclass(w.category, SyntaxWarning)
        ]
        self.assertEqual(
            syntax_warnings, [],
            f"bv.quoting.fuzzer emitted SyntaxWarnings: "
            f"{[str(w.message) for w in syntax_warnings]}",
        )

    def test_compileall_clean_under_wall(self):
        # Run `python -Wall -m compileall` on the whole tree. Any
        # SyntaxWarning becomes an error in strict modes and we want
        # to fail loudly here so CI catches future regressions.
        import subprocess
        repo = "/opt/safe-cli-repo"
        proc = subprocess.run(
            [sys.executable, "-Wall", "-m", "compileall", "-q", "bv", "bin"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=60,
        )
        # compileall exits 0 on success. We just want to know no SyntaxWarning
        # was printed.
        self.assertEqual(
            proc.returncode, 0,
            f"compileall -Wall failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        # The output must not contain the historic warning string.
        self.assertNotIn("invalid escape sequence", proc.stderr)
        self.assertNotIn("invalid escape sequence", proc.stdout)


if __name__ == "__main__":
    unittest.main()
