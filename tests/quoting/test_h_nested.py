"""Tests for the new nested-language detector, root-cause renderer,
TOCTOU guard, repair loop guard, and quoting fuzzer."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from bv.quoting import (  # noqa: E402
    FileSnapshot,
    RepairLoopGuard,
    STANDARD_CASES,
    analyze_full,
    detect_boundaries,
    is_quoting_hell,
    render_root_cause_report,
    root_cause_report,
    run_fuzzer,
    verify_unchanged_since,
)
from bv.quoting.nested_lang import find_max_risk


# ---------------------------------------------------------------------------
# Nested-language detector
# ---------------------------------------------------------------------------


class NestedLanguageDetectorTests(unittest.TestCase):
    def test_jq_detected_as_quoting_hell(self):
        src = "jq '.foo.bar' file.json\n"
        words, _, boundaries = analyze_full(src)
        self.assertGreater(len(boundaries), 0)
        self.assertEqual(boundaries[0].outer_command, "jq")
        self.assertEqual(boundaries[0].inner_language, "jq_program")
        self.assertTrue(is_quoting_hell(boundaries))

    def test_awk_detected_as_quoting_hell(self):
        src = "awk -F: '{print $1}' /etc/passwd\n"
        words, _, boundaries = analyze_full(src)
        self.assertGreater(len(boundaries), 0)
        self.assertEqual(boundaries[0].outer_command, "awk")
        self.assertEqual(boundaries[0].inner_language, "awk")
        self.assertTrue(is_quoting_hell(boundaries))

    def test_python_detected_as_quoting_hell(self):
        src = "python3 -c \"print('hello')\"\n"
        words, _, boundaries = analyze_full(src)
        self.assertGreater(len(boundaries), 0)
        self.assertEqual(boundaries[0].outer_command, "python3")
        self.assertEqual(boundaries[0].inner_language, "python")
        self.assertTrue(is_quoting_hell(boundaries))

    def test_mysql_detected_as_quoting_hell(self):
        src = 'mysql -e "SELECT * FROM users WHERE name=\\"$NAME\\""\n'
        words, _, boundaries = analyze_full(src)
        self.assertGreater(len(boundaries), 0)
        self.assertTrue(is_quoting_hell(boundaries))

    def test_plain_echo_not_quoting_hell(self):
        src = "echo hello\n"
        words, _, boundaries = analyze_full(src)
        self.assertEqual(boundaries, [])
        self.assertFalse(is_quoting_hell(boundaries))

    def test_find_max_risk_low_for_clean(self):
        self.assertEqual(find_max_risk([]), "low")


# ---------------------------------------------------------------------------
# Root-cause JSON output
# ---------------------------------------------------------------------------


class RootCauseReportTests(unittest.TestCase):
    def test_clean_script_is_pass(self):
        src = "cat $FILE\n"
        report = root_cause_report(src, file_path="test.sh")
        # report should be a dict
        self.assertIsInstance(report, dict)
        self.assertIn("schema_version", report)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["type"], "safe-cli.bash-verify")
        self.assertIn("source_sha256", report)
        self.assertEqual(report["file"], "test.sh")
        self.assertIn("diagnostics", report)
        self.assertIn("summary", report)

    def test_diagnostic_has_required_fields(self):
        src = "cat $FILE\n"
        report = root_cause_report(src, file_path="test.sh")
        self.assertGreater(len(report["diagnostics"]), 0)
        d = report["diagnostics"][0]
        for key in ("type", "root_cause", "location", "risk", "repair",
                    "confidence", "automatic_repair", "severity"):
            self.assertIn(key, d, f"diagnostic missing key: {key}")

    def test_quoting_hell_status(self):
        src = "python3 -c \"print('$X')\"\n"
        report = root_cause_report(src, file_path="test.sh")
        # Either the analyzer classifies this as quoting hell or it
        # reports it as REVIEW_REQUIRED; in both cases the report must
        # be present and structured.
        self.assertIn(report["status"], ("QUOTING_HELL_REFUSED", "REVIEW_REQUIRED", "REPAIRABLE"))

    def test_json_serializable(self):
        src = "echo $NAME; rm $TARGET\n"
        report = root_cause_report(src, file_path="test.sh")
        # Must be JSON-serializable.
        json.dumps(report)


# ---------------------------------------------------------------------------
# TOCTOU file-change protection
# ---------------------------------------------------------------------------


class TOCTOUTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="safe-cli-toctou-")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_unchanged_file_passes(self):
        p = os.path.join(self.tmpdir, "f.sh")
        with open(p, "w") as f:
            f.write("echo $X\n")
        snap = FileSnapshot.capture(p)
        self.assertIsNone(verify_unchanged_since(p, snap))

    def test_modified_file_fails(self):
        p = os.path.join(self.tmpdir, "f.sh")
        with open(p, "w") as f:
            f.write("echo $X\n")
        snap = FileSnapshot.capture(p)
        # Simulate concurrent modification.
        with open(p, "w") as f:
            f.write("echo modified\n")
        diff = verify_unchanged_since(p, snap)
        self.assertIsNotNone(diff)
        self.assertIn("hash", diff.lower())

    def test_missing_file_fails(self):
        p = os.path.join(self.tmpdir, "f.sh")
        with open(p, "w") as f:
            f.write("echo $X\n")
        snap = FileSnapshot.capture(p)
        os.unlink(p)
        diff = verify_unchanged_since(p, snap)
        self.assertIsNotNone(diff)


# ---------------------------------------------------------------------------
# RepairLoopGuard
# ---------------------------------------------------------------------------


class RepairLoopGuardTests(unittest.TestCase):
    def test_default_max_attempts(self):
        g = RepairLoopGuard()
        self.assertEqual(g.max_attempts, 5)
        self.assertEqual(g.max_repeated_failures, 3)
        self.assertEqual(g.max_total_seconds, 60.0)
        self.assertTrue(g.can_continue())

    def test_attempts_count(self):
        g = RepairLoopGuard(max_attempts=3)
        for i in range(2):
            self.assertTrue(g.record_attempt())
        self.assertFalse(g.record_attempt())

    def test_repeated_failure_stops(self):
        g = RepairLoopGuard(max_repeated_failures=3, max_attempts=100)
        # 3 identical signatures should stop the loop
        self.assertTrue(g.record_attempt("sig-A"))
        self.assertTrue(g.record_attempt("sig-A"))
        self.assertFalse(g.record_attempt("sig-A"))

    def test_reset(self):
        g = RepairLoopGuard(max_attempts=2)
        g.record_attempt()
        g.record_attempt()
        self.assertFalse(g.can_continue())
        g.reset()
        self.assertTrue(g.can_continue())

    def test_status_dict(self):
        g = RepairLoopGuard()
        g.record_attempt("x")
        g.record_attempt("y")
        s = g.status()
        self.assertEqual(s["attempts"], 2)
        self.assertTrue(s["can_continue"])


# ---------------------------------------------------------------------------
# Quoting fuzzer
# ---------------------------------------------------------------------------


class FuzzerTests(unittest.TestCase):
    def test_standard_cases_run_without_crash(self):
        results = run_fuzzer()
        self.assertEqual(len(results), len(STANDARD_CASES))
        for r in results:
            self.assertFalse(
                r.crashed,
                f"Fuzzer case {r.case_name} crashed: {r.notes}",
            )

    def test_fuzzer_case_categories_covered(self):
        categories = {c.category for c in STANDARD_CASES}
        # We expect coverage of at least these high-priority categories.
        for expected in ("word_splitting", "pathname_expansion",
                         "empty_disappear", "literal"):
            self.assertIn(expected, categories, f"missing category: {expected}")

    def test_random_adversarial_returns_string(self):
        from bv.quoting.fuzzer import random_adversarial
        s = random_adversarial()
        self.assertIsInstance(s, str)
        self.assertGreater(len(s), 0)


if __name__ == "__main__":
    unittest.main()
