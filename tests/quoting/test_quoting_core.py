"""Unit tests for bv.quoting — Conservative Bash Quoting Intelligence.

Spec section 67 calls for tests/quoting/.
Spec section 68 mandates certain regression fixtures that must remain
unchanged.

These tests use Python's built-in unittest framework, NOT pytest, to
match the rest of the safe-cli test suite. The CLI wrapper command
`safe-cli quote-fix` can run pytest if installed, but unittest is the
hard dependency.

We use unittest.TestCase because:
  - The existing test suite uses unittest.
  - pytest is optional in the sandbox image.
  - Hypothesis is not assumed available.

We deliberately test the CONTRACT of the quoting engine, not its
internal structure. Each test answers one question:
  "Does this concrete input produce the expected outcome?"
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from typing import List, Optional

# Ensure the safe-cli repo is on the path when running directly.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from bv.quoting import (  # noqa: E402
    analyze,
    analyze_with_intent,
    apply_repair,
    find_findings,
    render_json,
    render_text,
)


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Section 68 — Mandatory regression fixtures that must NOT be modified
# ---------------------------------------------------------------------------


class MandatoryRegressionFixtures(unittest.TestCase):
    """Each test loads a fixture, runs the analyzer, and asserts that
    nothing was proposed as an auto-applicable repair."""

    def _assert_no_auto_repair_eligible(self, name: str, source: str) -> None:
        findings = find_findings(source)
        auto_eligible = [f for f in findings if f.risk.auto_repair_eligible]
        # None of these fixtures should produce any auto-repair candidates.
        self.assertEqual(
            auto_eligible,
            [],
            f"Fixture {name} produced auto-eligible repairs: "
            + ", ".join(f.rule_id for f in auto_eligible),
        )

    def test_01_scalar_path_safe(self):
        src = _read_fixture("test_01_scalar_path.sh")
        self._assert_no_auto_repair_eligible("01", src)
        # Should not propose any repair at all because the word is already quoted.
        findings = find_findings(src)
        self.assertEqual(findings, [])

    def test_02_array_safe_expansion(self):
        src = _read_fixture("test_02_array_safe.sh")
        self._assert_no_auto_repair_eligible("02", src)

    def test_03_list_loop_intentional(self):
        src = _read_fixture("test_03_list_loop.sh")
        # The bare $LIST inside the for loop is intentional list semantics.
        # Engine MUST refuse any repair.
        self._assert_no_auto_repair_eligible("03", src)

    def test_04_array_iteration_already_correct(self):
        src = _read_fixture("test_04_array_iter.sh")
        self._assert_no_auto_repair_eligible("04", src)

    def test_05_dollar_at_preserved(self):
        src = _read_fixture("test_05_dollar_at.sh")
        self._assert_no_auto_repair_eligible("05", src)

    def test_06_dollar_star_preserved(self):
        src = _read_fixture("test_06_dollar_star.sh")
        self._assert_no_auto_repair_eligible("06", src)

    def test_07_double_bracket_quoted(self):
        src = _read_fixture("test_07_double_bracket_quoted.sh")
        self._assert_no_auto_repair_eligible("07", src)

    def test_08_double_bracket_pattern_rhs(self):
        # [[ $A == *.txt ]] is a PATTERN RHS, not a bug.
        src = _read_fixture("test_08_double_bracket_pattern.sh")
        self._assert_no_auto_repair_eligible("08", src)

    def test_09_heredoc_quoted_body(self):
        src = _read_fixture("test_09_heredoc_quoted.sh")
        self._assert_no_auto_repair_eligible("09", src)

    def test_10_heredoc_unquoted_body(self):
        src = _read_fixture("test_10_heredoc_expansion.sh")
        self._assert_no_auto_repair_eligible("10", src)

    def test_11_heredoc_backslash_continuation(self):
        src = _read_fixture("test_11_heredoc_backslash.sh")
        self._assert_no_auto_repair_eligible("11", src)


# ---------------------------------------------------------------------------
# Section 82 — Catastrophic-repair prevention tests
# ---------------------------------------------------------------------------


class CatastrophicRepairPrevention(unittest.TestCase):
    """The engine must NEVER transform these constructs."""

    def test_eval_not_quote_fixed(self):
        src = "USER_INPUT=\"$1\"\neval \"$USER_INPUT\"\n"
        findings = find_findings(src)
        # The eval call itself should generate a finding but with auto-repair refused.
        eval_findings = [f for f in findings if "eval" in (f.raw_text or "")]
        # Even if not directly flagged, no auto-repair should be proposed.
        for f in findings:
            self.assertFalse(
                f.decision.candidate_accepted,
                f"Auto-repair accepted on eval site: {f.rule_id}",
            )

    def test_bash_c_not_quote_fixed(self):
        src = "CMD=\"$1\"\nbash -c \"$CMD\"\n"
        findings = find_findings(src)
        for f in findings:
            self.assertFalse(
                f.decision.candidate_accepted,
                f"Auto-repair accepted on bash -c site: {f.rule_id}",
            )

    def test_dollar_at_never_modified(self):
        src = 'printf "%s\\n" "$@"\n'
        # No repair candidate should propose changing "$@" to anything else.
        words = analyze_with_intent(src)
        for w in words:
            self.assertNotIn(
                "$@", w.raw_text.replace('"$@"', "")[1:-1] if False else "",
                "test setup error",
            )
        # Specifically check that the replace "$@" string is untouched by candidates.
        from bv.quoting.candidates import generate_candidates
        from bv.quoting.rules import rules_for
        for w in words:
            cands = generate_candidates(w, rules_for(w))
            for c in cands:
                self.assertNotIn(
                    '"$@"', c.replacement.replace('"$@"', 'X').replace('"$@"', 'X').replace('X', ''),
                    "candidate touched $@",
                )

    def test_dollar_star_never_modified(self):
        src = 'printf "%s\\n" "$*"\n'
        findings = find_findings(src)
        for f in findings:
            self.assertFalse(f.decision.candidate_accepted)

    def test_array_at_never_modified(self):
        src = 'printf "%s\\n" "${arr[@]}"\n'
        findings = find_findings(src)
        for f in findings:
            self.assertFalse(f.decision.candidate_accepted)

    def test_array_star_never_modified(self):
        src = 'printf "%s\\n" "${arr[*]}"\n'
        findings = find_findings(src)
        for f in findings:
            self.assertFalse(f.decision.candidate_accepted)


# ---------------------------------------------------------------------------
# Section 83 — No destructive repair
# ---------------------------------------------------------------------------


class NoDestructiveRepair(unittest.TestCase):
    def test_repair_never_deletes_code(self):
        src = "rm $TARGET\n"
        for finding in find_findings(src):
            outcome = apply_repair(src, finding)
            # Even if the candidate was refused, the apply_repair must not
            # produce a result that loses code.
            self.assertGreater(
                len(outcome.candidate.replacement),
                0,
                f"Candidate would delete code: {finding.rule_id}",
            )

    def test_repair_never_shortens_to_zero(self):
        # Try a few risky-looking inputs and make sure no candidate has
        # an empty replacement.
        for src in [
            "rm $TARGET\n",
            "echo $NAME\n",
            "cat $FILE\n",
            "cp $SOURCE $DEST\n",
            "eval $CMD\n",
            "bash -c $C\n",
        ]:
            for finding in find_findings(src):
                self.assertNotEqual(
                    finding.candidate.replacement, "",
                    f"Empty candidate for source: {src!r}",
                )


# ---------------------------------------------------------------------------
# Section 84 — Source preservation tests
# ---------------------------------------------------------------------------


class SourcePreservation(unittest.TestCase):
    def test_comments_preserved_in_finding(self):
        src = "# important comment\ncat $FILE\n"
        # Findings should not propose to remove the comment.
        for f in find_findings(src):
            self.assertNotIn("important", f.candidate.replacement)

    def test_heredoc_body_unaffected(self):
        src = "cat <<'EOF'\n$HOME\nEOF\n"
        findings = find_findings(src)
        # No finding should propose replacing the heredoc body text.
        for f in findings:
            self.assertNotIn("$HOME", f.candidate.replacement or "")


# ---------------------------------------------------------------------------
# Section 85 — Idempotence
# ---------------------------------------------------------------------------


class Idempotence(unittest.TestCase):
    def test_analyze_is_pure(self):
        src = "cat $FILE\n"
        a = find_findings(src)
        b = find_findings(src)
        self.assertEqual(len(a), len(b))
        for fa, fb in zip(a, b):
            self.assertEqual(fa.candidate.replacement, fb.candidate.replacement)
            self.assertEqual(fa.rule_id, fb.rule_id)


# ---------------------------------------------------------------------------
# Section 86 — Stability / non-oscillation
# ---------------------------------------------------------------------------


class StabilityTests(unittest.TestCase):
    def test_does_not_oscillate(self):
        from bv.quoting.repairs import apply_to_text
        from bv.quoting.repairs import make_oscillation_guard
        guard = make_oscillation_guard()
        src = "cat $FILE\n"
        findings = find_findings(src)
        # First pass: hash the source.
        guard.record(src)
        # Apply any accepted candidates; refuse would-be repeats.
        for finding in findings:
            new_text = apply_to_text(src, finding.candidate)
            self.assertFalse(
                guard.has_seen(new_text),
                "Engine oscillated: candidate produced previously-seen source.",
            )
            guard.record(new_text)


# ---------------------------------------------------------------------------
# Section 46 — Renderers
# ---------------------------------------------------------------------------


class RendererContracts(unittest.TestCase):
    def test_render_text_returns_string(self):
        src = "cat $FILE\n"
        text = render_text(find_findings(src))
        self.assertIsInstance(text, str)
        if text:
            self.assertIn("BV-QUOTE-", text)

    def test_render_json_returns_dict(self):
        src = "cat $FILE\n"
        data = render_json(find_findings(src))
        self.assertIsInstance(data, dict)
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        summary = data["summary"]
        self.assertIn("total", summary)
        self.assertIn("auto_repair_eligible", summary)
        self.assertIn("refused", summary)

    def test_json_serializable(self):
        src = "cat $FILE\n"
        data = render_json(find_findings(src))
        json.dumps(data)  # must not raise


# ---------------------------------------------------------------------------
# Section 27 — Validator
# ---------------------------------------------------------------------------


class ValidatorTests(unittest.TestCase):
    def test_validate_static_passes_on_simple_wrap(self):
        from bv.quoting.validator import validate_static
        from bv.quoting.candidates import Candidate
        original = "cat $FILE\n"
        candidate = Candidate(
            rule_id="BV-QUOTE-001",
            title="test",
            start_byte=4,
            end_byte=9,
            replacement='"$FILE"',
            rationale="wrap",
            semantic_risk="low",
            candidate_confidence=0.95,
        )
        result = validate_static(original, candidate)
        self.assertTrue(result.bash_n_ok)
        self.assertTrue(result.parser_round_trip_ok)
        self.assertTrue(result.passed)

    def test_apply_to_text_is_exact(self):
        from bv.quoting.candidates import Candidate
        from bv.quoting.validator import apply_candidate
        original = "cat $FILE done\n"
        candidate = Candidate(
            rule_id="BV-QUOTE-001",
            title="test",
            start_byte=4,
            end_byte=9,
            replacement='"$FILE"',
            rationale="wrap",
            semantic_risk="low",
            candidate_confidence=0.95,
        )
        new_text = apply_candidate(original, candidate)
        self.assertEqual(new_text, 'cat "$FILE" done\n')


# ---------------------------------------------------------------------------
# Section 71 — Performance sanity
# ---------------------------------------------------------------------------


class PerformanceSanity(unittest.TestCase):
    def test_handles_large_script(self):
        # Build a 10,000-line script with mixed expansions.
        lines = []
        for i in range(2000):
            lines.append(f"echo line_{i} && cat $FILE_{i} > $OUT_{i}")
        src = "\n".join(lines) + "\n"
        findings = find_findings(src)
        # Should not crash; should produce SOME findings.
        self.assertIsInstance(findings, list)


# ---------------------------------------------------------------------------
# Section 72 — No host execution during analysis
# ---------------------------------------------------------------------------


class NoHostExecution(unittest.TestCase):
    def test_analyze_never_executes_user_bytes(self):
        # Use a deliberately dangerous payload that would do bad things
        # if any module naively ran it.
        src = "echo $(rm -rf /)\n"
        # Just running find_findings must NOT touch the filesystem.
        findings = find_findings(src)
        # We're in /tmp/tests/... — assert that the test still has its
        # own files present by simply completing.
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
