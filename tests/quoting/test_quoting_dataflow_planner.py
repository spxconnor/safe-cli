"""Tests for dataflow + planner modules."""
from __future__ import annotations

import os
import sys
import unittest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from bv.quoting.dataflow import (  # noqa: E402
    apply_dataflow,
    build_taint_map,
    sink_for_command,
)
from bv.quoting.planner import (  # noqa: E402
    OscillationGuard,
    RepairBudget,
    plan,
)
from bv.quoting.candidates import Candidate  # noqa: E402
from bv.quoting.risk import assess  # noqa: E402
from bv.quoting.rules import rules_for  # noqa: E402
from bv.quoting.model import (  # noqa: E402
    ContextKind,
    Expansion,
    Intent,
    QuoteType,
    SemanticFlags,
    ShellWord,
)


class TaintMapTests(unittest.TestCase):
    def test_env_var_is_tainted(self):
        m = build_taint_map("")
        self.assertTrue(m.get("HOME"))
        self.assertTrue(m.get("USER"))

    def test_positional_is_tainted(self):
        m = build_taint_map("")
        self.assertTrue(m.get("1"))
        self.assertTrue(m.get("@"))

    def test_assignment_propagates(self):
        m = build_taint_map("X=$1\n")
        self.assertTrue(m.get("X"))

    def test_assignment_from_cmd_subst_propagates(self):
        m = build_taint_map("X=$(cat foo)\n")
        self.assertTrue(m.get("X"))

    def test_literal_assignment_not_tainted(self):
        m = build_taint_map("X=hello\n")
        self.assertFalse(m.get("X"))

    def test_chain_propagates(self):
        m = build_taint_map("A=$1\nB=$A\nC=$B\n")
        self.assertTrue(m.get("C"))


class SinkDetectionTests(unittest.TestCase):
    def test_eval_is_sink(self):
        self.assertEqual(sink_for_command("eval"), "eval")

    def test_curl_is_sink(self):
        self.assertEqual(sink_for_command("curl"), "curl")

    def test_rm_is_sink(self):
        self.assertEqual(sink_for_command("rm"), "rm")

    def test_safe_command_is_not_sink(self):
        self.assertIsNone(sink_for_command("echo"))

    def test_no_command_is_not_sink(self):
        self.assertIsNone(sink_for_command(None))


def _make_word(*, raw="$VAR", context=ContextKind.COMMAND_ARG, intent=Intent.UNKNOWN, conf=0.0, cmd="cat", user_controlled=False):
    return ShellWord(
        start_byte=0,
        end_byte=len(raw),
        start_line=1,
        start_column=1,
        raw_text=raw,
        quote_type=QuoteType.NONE,
        has_parameter_expansion=True,
        expansions=(Expansion(kind="parameter", raw=raw, start=0, end=len(raw), name=raw.lstrip("$").rstrip("}")),),
        context_kind=context,
        command_name=cmd,
        semantic=SemanticFlags(
            parameter_expansion=True,
            word_splitting_possible=True,
            empty_value_can_disappear=True,
        ),
        intent=intent,
        intent_confidence=conf,
        intent_evidence=(),
        user_controlled=user_controlled,
    )


class PlannerNoGoTests(unittest.TestCase):
    """The planner must REFUSE these candidates."""

    def test_refuses_eval_sink(self):
        w = _make_word(cmd="eval")
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=4,
            replacement='"$VAR"',
            rationale="wrap",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, "$VAR")
        self.assertFalse(decision.candidate_accepted)

    def test_refuses_dollar_at(self):
        w = _make_word(raw='"$@"')
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=4,
            replacement='"$@"',
            rationale="noop",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, '"$@"')
        self.assertFalse(decision.candidate_accepted)

    def test_refuses_array_at(self):
        w = _make_word(raw="${arr[@]}")
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=10,
            replacement='"${arr[@]}"',
            rationale="noop",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, "${arr[@]}")
        self.assertFalse(decision.candidate_accepted)

    def test_refuses_command_name_change(self):
        w = _make_word(raw="rm $TARGET")
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=10,
            replacement="trash $TARGET",
            rationale="bad",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, "rm $TARGET")
        self.assertFalse(decision.candidate_accepted)

    def test_refuses_deletion(self):
        w = _make_word(raw="$VAR")
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=4,
            replacement="",
            rationale="bad",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, "$VAR")
        self.assertFalse(decision.candidate_accepted)

    def test_refuses_byte_budget_overflow(self):
        w = _make_word(raw="x")
        cand = Candidate(
            rule_id="BV-QUOTE-001",
            title="wrap",
            start_byte=0,
            end_byte=1,
            replacement="x" + "y" * 200,
            rationale="bad",
            semantic_risk="low",
            candidate_confidence=0.99,
        )
        rs = rules_for(w)
        risk = assess(w, rs)
        decision = plan(w, cand, risk, rs, "x", budget=RepairBudget(max_changed_bytes=128))
        self.assertFalse(decision.candidate_accepted)


class OscillationGuardTests(unittest.TestCase):
    def test_first_time_seen(self):
        g = OscillationGuard()
        self.assertFalse(g.has_seen("abc"))

    def test_records_and_recognizes(self):
        g = OscillationGuard()
        g.record("abc")
        self.assertTrue(g.has_seen("abc"))
        self.assertFalse(g.has_seen("def"))


if __name__ == "__main__":
    unittest.main()
