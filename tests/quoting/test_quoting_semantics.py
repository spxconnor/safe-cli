"""Tests for the semantics module — Bash expansion classification."""
from __future__ import annotations

import os
import sys
import unittest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from bv.quoting.semantics import (  # noqa: E402
    ExpansionKind,
    classify_expansion,
    classify_intent,
    compute_semantic_flags,
    has_unquoted_glob_metachars,
    in_assignment_rhs,
    in_redirection,
    in_test_bracket,
    is_dangerously_array_ambiguous,
    is_intentionally_list_form,
)


class ExpansionClassificationTests(unittest.TestCase):
    def test_dollar_at(self):
        self.assertEqual(classify_expansion("$@"), ExpansionKind.IS_DOLLAR_AT)

    def test_dollar_star(self):
        self.assertEqual(classify_expansion("$*"), ExpansionKind.IS_DOLLAR_STAR)

    def test_simple_param(self):
        self.assertEqual(classify_expansion("$FOO"), ExpansionKind.IS_SIMPLE_PARAM)

    def test_braced_param(self):
        self.assertEqual(classify_expansion("${FOO}"), ExpansionKind.IS_BRACED_PARAM)

    def test_cmd_subst_dollar(self):
        self.assertEqual(classify_expansion("$(echo hi)"), ExpansionKind.IS_CMD_SUBST_DOLLAR)

    def test_cmd_subst_backtick(self):
        self.assertEqual(classify_expansion("`echo hi`"), ExpansionKind.IS_CMD_SUBST_BACKTICK)

    def test_arith(self):
        self.assertEqual(classify_expansion("$((1+2))"), ExpansionKind.IS_ARITH)

    def test_array_at(self):
        self.assertEqual(classify_expansion("${arr[@]}"), ExpansionKind.IS_ARRAY_AT)

    def test_array_star(self):
        self.assertEqual(classify_expansion("${arr[*]}"), ExpansionKind.IS_ARRAY_STAR)


class ArraySemanticTests(unittest.TestCase):
    def test_dollar_at_is_intentionally_list(self):
        self.assertTrue(is_intentionally_list_form("$@"))

    def test_dollar_at_is_dangerously_array_ambiguous(self):
        self.assertTrue(is_dangerously_array_ambiguous("$@"))

    def test_dollar_star_is_dangerously_array_ambiguous(self):
        self.assertTrue(is_dangerously_array_ambiguous("$*"))

    def test_array_at_is_dangerously_array_ambiguous(self):
        self.assertTrue(is_dangerously_array_ambiguous("${arr[@]}"))

    def test_simple_param_not_list(self):
        self.assertFalse(is_intentionally_list_form("$VAR"))
        self.assertFalse(is_dangerously_array_ambiguous("$VAR"))


class GlobTests(unittest.TestCase):
    def test_plain_glob(self):
        self.assertTrue(has_unquoted_glob_metachars("*.txt"))

    def test_quoted_glob_excluded(self):
        # The function strips both single- and double-quoted spans so
        # a glob char inside a quoted span does NOT count.
        self.assertFalse(has_unquoted_glob_metachars('"$FILE"'))
        self.assertFalse(has_unquoted_glob_metachars("'*.txt'"))

    def test_unquoted_glob_in_mixed_text(self):
        # `*.txt` outside any quotes IS detected.
        self.assertTrue(has_unquoted_glob_metachars('"$DIR"/*.txt'))


class IntentTests(unittest.TestCase):
    def _make_word(self, raw: str, context_kind):
        from bv.quoting.model import (
            ContextKind,
            Expansion,
            Intent,
            QuoteType,
            SemanticFlags,
            ShellWord,
        )
        return ShellWord(
            start_byte=0,
            end_byte=len(raw),
            start_line=1,
            start_column=1,
            raw_text=raw,
            quote_type=QuoteType.NONE,
            has_parameter_expansion="$" in raw and "`" not in raw and "(" not in raw,
            has_command_substitution="`" in raw or "$(" in raw,
            expansions=(Expansion(kind="parameter", raw=raw, start=0, end=len(raw), name=raw.lstrip("$").rstrip("}")),) if "$" in raw else (),
            context_kind=context_kind,
            semantic=SemanticFlags(),
            intent=Intent.UNKNOWN,
            intent_confidence=0.0,
            intent_evidence=(),
            user_controlled=False,
        )

    def test_file_is_intent_path(self):
        from bv.quoting.model import ContextKind
        w = self._make_word("$FILE", ContextKind.COMMAND_ARG)
        intent, conf, _ = classify_intent(w)
        self.assertEqual(intent.value, "path")
        self.assertGreaterEqual(conf, 0.5)

    def test_home_is_intent_path(self):
        from bv.quoting.model import ContextKind
        w = self._make_word("$HOME", ContextKind.COMMAND_ARG)
        intent, conf, _ = classify_intent(w)
        self.assertEqual(intent.value, "path")

    def test_unknown_intent_for_random_name(self):
        from bv.quoting.model import ContextKind
        w = self._make_word("$XYZZY", ContextKind.COMMAND_ARG)
        intent, _, _ = classify_intent(w)
        self.assertEqual(intent.value, "unknown")


class ContextTests(unittest.TestCase):
    def _make_word(self, context_kind):
        from bv.quoting.model import (
            ContextKind,
            Expansion,
            Intent,
            QuoteType,
            SemanticFlags,
            ShellWord,
        )
        return ShellWord(
            start_byte=0,
            end_byte=4,
            start_line=1,
            start_column=1,
            raw_text="$VAR",
            quote_type=QuoteType.NONE,
            has_parameter_expansion=True,
            expansions=(Expansion(kind="parameter", raw="$VAR", start=0, end=4, name="VAR"),),
            context_kind=context_kind,
            semantic=SemanticFlags(),
            intent=Intent.UNKNOWN,
            intent_confidence=0.0,
            intent_evidence=(),
            user_controlled=False,
        )

    def test_assignment_no_splitting(self):
        from bv.quoting.model import ContextKind
        w = self._make_word(ContextKind.ASSIGNMENT)
        sem = compute_semantic_flags(w)
        # Word splitting does NOT happen in assignment RHS
        self.assertFalse(sem.word_splitting_possible)
        # But pathname expansion also does NOT happen there
        self.assertFalse(sem.pathname_expansion_possible)

    def test_double_bracket_no_splitting(self):
        from bv.quoting.model import ContextKind
        w = self._make_word(ContextKind.TEST_DOUBLE_BRACKET)
        sem = compute_semantic_flags(w)
        self.assertFalse(sem.word_splitting_possible)


class HelperTests(unittest.TestCase):
    def test_in_assignment(self):
        from bv.quoting.model import ContextKind, QuoteType, Expansion, SemanticFlags, ShellWord, Intent
        w = ShellWord(0, 4, 1, 1, "$VAR", QuoteType.NONE, has_parameter_expansion=True,
                      expansions=(Expansion(kind="parameter", raw="$VAR", start=0, end=4, name="VAR"),),
                      context_kind=ContextKind.ASSIGNMENT, semantic=SemanticFlags(),
                      intent=Intent.UNKNOWN, intent_confidence=0.0, intent_evidence=(), user_controlled=False)
        self.assertTrue(in_assignment_rhs(w))


if __name__ == "__main__":
    unittest.main()
