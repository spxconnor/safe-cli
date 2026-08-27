"""Regression tests for severity comparison (P0 5 fix).

The severity labels MUST be compared ordinally, not lexically.
This file exercises every (actual, threshold) pair and asserts that
error-level diagnostics are always considered blocking when the
threshold is warning or stricter.
"""
import unittest

from bv.diagnostic import Diagnostic, LayerResult, Severity, Category


def make_diag(severity: Severity) -> Diagnostic:
    return Diagnostic(
        tool="test",
        category=Category.UNKNOWN,
        severity=severity,
        file="test.sh",
        line=1,
        message=f"a {severity.value} diagnostic",
    )


class TestSeverityComparison(unittest.TestCase):
    """Every (actual, threshold) combination must use the ordinal map."""

    LEVELS = [Severity.STYLE, Severity.INFO, Severity.WARNING, Severity.ERROR]

    def test_meets_threshold_ordinal(self):
        # Each level meets its own threshold and any stricter one
        for actual in self.LEVELS:
            for threshold in self.LEVELS:
                expected = self.LEVELS.index(actual) >= self.LEVELS.index(threshold)
                got = Severity.meets_threshold(actual, threshold)
                self.assertEqual(
                    got, expected,
                    f"meets_threshold({actual.value}, {threshold.value}) "
                    f"should be {expected} (got {got})",
                )

    def test_string_compare_was_buggy(self):
        """Document the BUG we are fixing.

        The old code used Severity(...).value >= ... which compares
        strings. Lexicographically "error" < "warning", so the old
        code wrongly treated errors as below the warning threshold.
        The fix routes everything through Severity.meets_threshold.
        """
        # Direct evidence: lexicographic comparison gives the wrong answer.
        self.assertGreater("warning", "error")
        # The new code uses the ordinal map and gets the right answer.
        self.assertTrue(Severity.meets_threshold(Severity.ERROR, Severity.WARNING))
        self.assertFalse(Severity.meets_threshold(Severity.STYLE, Severity.ERROR))

    def test_layer_result_above_threshold_finds_errors(self):
        """LayerResult.above_threshold(warning) must include error diagnostics.

        The bug: with string compare, "error" >= "warning" was False,
        so error-level diagnostics were silently dropped from the
        blocking list.
        """
        lr = LayerResult(layer="test", status="fail")
        lr.add(make_diag(Severity.STYLE))
        lr.add(make_diag(Severity.INFO))
        lr.add(make_diag(Severity.WARNING))
        lr.add(make_diag(Severity.ERROR))
        blocking = lr.above_threshold(Severity.WARNING)
        sev_values = {d.severity.value for d in blocking}
        self.assertIn("warning", sev_values)
        self.assertIn("error", sev_values)
        self.assertNotIn("style", sev_values)
        self.assertNotIn("info", sev_values)

    def test_above_threshold_strict_only(self):
        """When threshold is error, only error diagnostics block."""
        lr = LayerResult(layer="test", status="fail")
        lr.add(make_diag(Severity.WARNING))
        lr.add(make_diag(Severity.ERROR))
        blocking = lr.above_threshold(Severity.ERROR)
        self.assertEqual(len(blocking), 1)
        self.assertEqual(blocking[0].severity, Severity.ERROR)


if __name__ == "__main__":
    unittest.main()
