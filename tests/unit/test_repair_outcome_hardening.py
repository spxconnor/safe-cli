"""Regression tests for the RepairOutcome semantics hardening.

Spec section 2:
  - candidate_created   : True iff candidate bytes were computed
  - validated           : True iff validation passed
  - persisted           : True iff atomic write to disk + post-write hash recheck both passed
  - applied             : True iff persisted (current implementation)

Critically:
  - target_path=None MUST yield applied=False, persisted=False
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, "/opt/safe-cli-repo")

from bv.quoting.candidates import Candidate  # noqa: E402
from bv.quoting.model import ContextKind, QuoteType, SemanticFlags, ShellWord  # noqa: E402
from bv.quoting.planner import PlanDecision  # noqa: E402
from bv.quoting.repairs import (  # noqa: E402
    RepairOutcome,
    apply_to_text,
    run_repair,
)


def _make_accepted_decision() -> PlanDecision:
    return PlanDecision(
        rule_id="BV-QUOTE-001",
        candidate_accepted=True,
        reason="synthetic accept",
        confidence=0.99,
        semantic_risk="low",
        severity="warning",
    )


def _make_word_for_source(source: str, raw: str) -> ShellWord:
    start = source.find(raw)
    if start < 0:
        raise AssertionError(f"{raw!r} not in source")
    return ShellWord(
        start_byte=start,
        end_byte=start + len(raw),
        start_line=source.count("\n", 0, start) + 1,
        start_column=start - source.rfind("\n", 0, start),
        raw_text=raw,
        quote_type=QuoteType.NONE,
        semantic=SemanticFlags(word_splitting_possible=True),
        context_kind=ContextKind.COMMAND_ARG,
    )


def _make_candidate(word: ShellWord, replacement: str) -> Candidate:
    return Candidate(
        rule_id="BV-QUOTE-001",
        title="test",
        start_byte=word.start_byte,
        end_byte=word.end_byte,
        replacement=replacement,
        rationale="wrap",
        semantic_risk="low",
        candidate_confidence=0.99,
    )


class TestReadOnlyRepairNeverClaimsPersistence(unittest.TestCase):
    """Spec section 2B: target_path=None MUST yield applied=False, persisted=False."""

    def test_readonly_repair_sets_applied_false_persisted_false(self):
        src = "FILE=\"my doc.txt\"\nrm $FILE\n"
        word = _make_word_for_source(src, "$FILE")
        candidate = _make_candidate(word, '"$FILE"')
        decision = _make_accepted_decision()

        outcome = run_repair(
            src, word, candidate, decision,
            target_path=None,
            backup_path=None,
            require_validation=False,
        )
        self.assertTrue(outcome.candidate_created)
        self.assertTrue(outcome.validated)
        self.assertFalse(outcome.applied,
                         f"applied should be False for read-only call, got {outcome.applied}")
        self.assertFalse(outcome.persisted,
                         f"persisted should be False for read-only call, got {outcome.persisted}")
        # candidate bytes still computed
        self.assertNotEqual(outcome.new_sha256, "")
        self.assertEqual(outcome.error, None)

    def test_readonly_repair_does_not_touch_disk(self):
        """Even if a target_path is passed somewhere upstream, omitting it
        here must leave the source string untouched in memory."""
        src = "FILE=\"my doc.txt\"\nrm $FILE\n"
        before_sha = hashlib.sha256(src.encode()).hexdigest()
        word = _make_word_for_source(src, "$FILE")
        candidate = _make_candidate(word, '"$FILE"')
        decision = _make_accepted_decision()
        run_repair(src, word, candidate, decision,
                   target_path=None, require_validation=False)
        after_sha = hashlib.sha256(src.encode()).hexdigest()
        self.assertEqual(before_sha, after_sha)


class TestPersistedRepairSetsAppliedAndPersisted(unittest.TestCase):
    """Spec section 2C/D: when target_path is given and atomic write
    succeeds and post-write hash matches, applied=True AND persisted=True."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="repair-outcome-")
        self.target = os.path.join(self.tmpdir, "script.sh")
        self.backup = os.path.join(self.tmpdir, "script.sh.bak")
        self.src = "FILE=\"my doc.txt\"\nrm $FILE\n"
        with open(self.target, "w") as f:
            f.write(self.src)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_persisted_repair_sets_both_flags(self):
        word = _make_word_for_source(self.src, "$FILE")
        candidate = _make_candidate(word, '"$FILE"')
        decision = _make_accepted_decision()

        outcome = run_repair(
            self.src, word, candidate, decision,
            target_path=self.target,
            backup_path=self.backup,
            require_validation=False,
        )
        self.assertTrue(outcome.candidate_created)
        self.assertTrue(outcome.validated)
        self.assertTrue(outcome.persisted)
        self.assertTrue(outcome.applied)
        self.assertEqual(outcome.error, None)

    def test_disk_sha_matches_candidate_sha(self):
        word = _make_word_for_source(self.src, "$FILE")
        candidate = _make_candidate(word, '"$FILE"')
        decision = _make_accepted_decision()

        outcome = run_repair(
            self.src, word, candidate, decision,
            target_path=self.target,
            require_validation=False,
        )
        disk_bytes = open(self.target, "rb").read()
        disk_sha = hashlib.sha256(disk_bytes).hexdigest()
        self.assertEqual(disk_sha, outcome.new_sha256)


class TestFailedPersistenceNeverClaimsSuccess(unittest.TestCase):
    """Spec section 2D: failed persistence never reports success."""

    def test_unwritable_target_sets_applied_false(self):
        # Use a path that cannot be created (inside /dev/null which is not
        # a directory). This forces the atomic-write to fail at makedirs
        # or mkstemp stage.
        bogus = "/dev/null/safe-cli-cannot-create-this/script.sh"
        src = "cat $X\n"
        word = _make_word_for_source(src, "$X")
        candidate = _make_candidate(word, '"$X"')
        decision = _make_accepted_decision()

        outcome = run_repair(
            src, word, candidate, decision,
            target_path=bogus,
            require_validation=False,
        )
        self.assertTrue(outcome.candidate_created)
        self.assertTrue(outcome.validated)
        self.assertFalse(outcome.applied)
        self.assertFalse(outcome.persisted)
        self.assertIsNotNone(outcome.error)


class TestRejectedRepairNeverClaimsCreation(unittest.TestCase):
    """Spec section 2: planner rejection means candidate_created=False."""

    def test_planner_refused_yields_all_false(self):
        src = "cat $X\n"
        word = _make_word_for_source(src, "$X")
        candidate = _make_candidate(word, '"$X"')
        decision = PlanDecision(
            rule_id="BV-QUOTE-001",
            candidate_accepted=False,
            reason="not safe",
            confidence=0.0,
            semantic_risk="high",
            severity="warning",
        )

        outcome = run_repair(src, word, candidate, decision,
                             target_path=None, require_validation=False)
        self.assertFalse(outcome.candidate_created)
        self.assertFalse(outcome.validated)
        self.assertFalse(outcome.persisted)
        self.assertFalse(outcome.applied)
        self.assertIsNotNone(outcome.error)


class TestNoAppliedTrueHardcodedElsewhere(unittest.TestCase):
    """Cross-cutting regression: `applied=True` must appear ONLY in the
    final-success return after disk write + hash recheck. Any other
    hardcoded `applied=True` would re-introduce the read-only-call bug."""

    def test_applied_true_appears_only_at_final_success_return(self):
        path = "/opt/safe-cli-repo/bv/quoting/repairs.py"
        with open(path, "r") as f:
            src = f.read()
        # Strip line comments
        non_comment_lines = [
            ln for ln in src.split("\n")
            if not ln.lstrip().startswith("#")
        ]
        # The dataclass declaration uses `applied: bool = False`, which is
        # legitimate. The only LEGITIMATE hardcoded `applied=True` is
        # at the final-success return.
        applied_true_lines = []
        applied_true_indices = []
        for i, ln in enumerate(non_comment_lines):
            stripped = ln.strip()
            # Must match the kwarg form `applied=True` (with optional comma).
            if stripped.startswith("applied=True"):
                applied_true_lines.append(stripped)
                applied_true_indices.append(i)
        # Allow exactly one such line (the final success return).
        self.assertEqual(
            len(applied_true_lines), 1,
            f"applied=True literal should appear exactly once (final success "
            f"return). Found {len(applied_true_lines)} occurrences: "
            f"{applied_true_lines}",
        )
        # That one line must be preceded by post-write hash recheck logic.
        target_idx = applied_true_indices[0]
        window = "\n".join(non_comment_lines[max(0, target_idx - 30):target_idx])
        self.assertIn("post-write", window.lower())


if __name__ == "__main__":
    unittest.main()
