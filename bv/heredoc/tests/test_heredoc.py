"""bv/heredoc/tests/test_heredoc.py - comprehensive fixtures.

Covers basic forms, semantic classification, backslash, indentation,
multiple/nested heredocs, missing terminator, edge cases, the
protected-region API, and resource bounds.
"""
import sys
import unittest

sys.path.insert(0, "/opt/safe-cli-repo")

from bv.heredoc import scan_heredocs, analyze, is_inside_heredoc_body


# Basic forms

class TestBasicForms(unittest.TestCase):
    def test_unquoted_basic(self):
        src = "cat <<EOF" + chr(10) + "hello" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["delimiter"], "EOF")
        self.assertIsNone(h[0]["quote_style"])
        self.assertFalse(h[0]["strip_tabs"])
        self.assertTrue(h[0]["terminated"])

    def test_single_quoted(self):
        src = "cat <<'EOF'" + chr(10) + "literal $USER" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(h[0]["quote_style"], "'")
        self.assertEqual(h[0]["delimiter"], "EOF")

    def test_double_quoted(self):
        src = 'cat <<"EOF"' + chr(10) + "literal-ish $USER" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(h[0]["quote_style"], '"')
        self.assertEqual(h[0]["delimiter"], "EOF")

    def test_backslash_escape(self):
        src = "cat <<" + chr(92) + "EOF" + chr(10) + "hello $USER" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(h[0]["quote_style"], chr(92))
        self.assertEqual(h[0]["delimiter"], "EOF")

    def test_strip_tabs_marker(self):
        src = "cat <<-EOF" + chr(10) + chr(9) + "hello" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(h[0]["operator"], "<<-")
        self.assertTrue(h[0]["strip_tabs"])

    def test_terminator_with_tab_stripping(self):
        # <<- strips leading TABS from terminator; the body keeps original whitespace
        src = "cat <<-EOF" + chr(10) + "    hello" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertTrue(h[0]["strip_tabs"])
        self.assertTrue(h[0]["terminated"])
        self.assertIn("    hello", h[0]["body"])


# Semantic classification

class TestSemantics(unittest.TestCase):
    def test_unquoted_with_param_expansion(self):
        src = "cat <<EOF" + chr(10) + "$HOME" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertTrue(a[0].semantics.expansion_enabled)
        self.assertTrue(a[0].semantics.parameter_expansion)

    def test_unquoted_with_command_substitution(self):
        src = "cat <<EOF" + chr(10) + "$(date)" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertTrue(a[0].semantics.command_substitution)

    def test_unquoted_with_arithmetic(self):
        src = "cat <<EOF" + chr(10) + "$((1+2))" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertTrue(a[0].semantics.arithmetic_expansion)

    def test_single_quoted_literal(self):
        # $HOME inside 'EOF' is literal text, NOT parameter expansion
        src = "cat <<'EOF'" + chr(10) + "$HOME" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertFalse(a[0].semantics.expansion_enabled)
        self.assertFalse(a[0].semantics.parameter_expansion)
        self.assertTrue(a[0].semantics.quoted_literal_mode)

    def test_double_quoted_literal(self):
        src = 'cat <<"EOF"' + chr(10) + "$HOME" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertFalse(a[0].semantics.expansion_enabled)
        self.assertTrue(a[0].semantics.quoted_literal_mode)


# Backslash semantics

class TestBackslash(unittest.TestCase):
    def test_backslash_newline_continuation(self):
        # In unquoted heredoc, "\
        # In unquoted heredoc, backslash-newline means line continuation
        src = "cat <<EOF" + chr(10) + "hello " + chr(92) + chr(10) + "world" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        self.assertTrue(len(a[0].semantics.backslash_newline_continuations) >= 1)

    def test_literal_backslash_preserved(self):
        src = "cat <<'EOF'" + chr(10) + "hello " + chr(92) + chr(10) + "world" + chr(10) + "EOF" + chr(10)
        a = analyze(src)
        # Single-quoted: backslash is literal, NO continuation
        self.assertEqual(len(a[0].semantics.backslash_newline_continuations), 0)


# Indentation rules

class TestIndentation(unittest.TestCase):
    def test_unquoted_exact_terminator_match(self):
        # Leading spaces before terminator make it MALFORMED for <<
        src = "cat <<EOF" + chr(10) + "hello" + chr(10) + "    EOF" + chr(10)
        h = scan_heredocs(src)
        # Terminator on line 3 has 4 leading spaces; not exact match
        self.assertFalse(h[0]["terminated"])

    def test_strip_tabs_only(self):
        # <<- strips ONLY tabs from terminator, not spaces
        src = "cat <<-EOF" + chr(10) + "hello" + chr(10) + "    EOF" + chr(10)
        h = scan_heredocs(src)
        # 4-space-indented EOF: <<- does not accept it
        self.assertFalse(h[0]["terminated"])


# Multiple / nested

class TestMultipleAndNesting(unittest.TestCase):
    def test_multiple_heredocs(self):
        src = "cat <<A" + chr(10) + "one" + chr(10) + "A" + chr(10) + "cat <<B" + chr(10) + "two" + chr(10) + "B" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(len(h), 2)
        self.assertEqual([x["delimiter"] for x in h], ["A", "B"])
        self.assertTrue(all(x["terminated"] for x in h))

    def test_nested_heredocs_both_detected(self):
        # Line-based scanner detects each `<<X` -> `X` terminator pair
        # independently. For nested: finds OUTER and INNER as two heredocs.
        src = (
            "bash <<OUTER" + chr(10) +
            "cat <<INNER" + chr(10) +
            "hello" + chr(10) +
            "INNER" + chr(10) +
            "OUTER" + chr(10)
        )
        h = scan_heredocs(src)
        self.assertEqual(len(h), 2)
        delims = [x["delimiter"] for x in h]
        self.assertEqual(delims, ["OUTER", "INNER"])
        self.assertIn("INNER", h[0]["body"])
        self.assertIn("hello", h[1]["body"])
        self.assertNotIn("OUTER", h[1]["body"])


# Edge cases

class TestEdgeCases(unittest.TestCase):
    def test_unterminated(self):
        src = "cat <<EOF" + chr(10) + "hello" + chr(10)
        h = scan_heredocs(src)
        self.assertEqual(len(h), 1)
        self.assertFalse(h[0]["terminated"])

    def test_delimiter_inside_body(self):
        # "EOF-not-a-terminator" must NOT be treated as the terminator
        src = (
            "cat <<EOF" + chr(10) +
            "EOF-not-a-terminator" + chr(10) +
            "hello" + chr(10) +
            "EOF" + chr(10)
        )
        h = scan_heredocs(src)
        self.assertTrue(h[0]["terminated"])
        self.assertIn("EOF-not-a-terminator", h[0]["body"])
        self.assertIn("hello", h[0]["body"])

    def test_empty_body(self):
        src = "cat <<EOF" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertTrue(h[0]["terminated"])
        self.assertEqual(h[0]["body"], "")

    def test_empty_quoted_body(self):
        src = "cat <<'EOF'" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertTrue(h[0]["terminated"])
        self.assertEqual(h[0]["body"], "")

    def test_body_with_quotes(self):
        src = "cat <<EOF" + chr(10) + chr(34) + "hello" + chr(34) + chr(10) + "'world'" + chr(10) + "EOF" + chr(10)
        h = scan_heredocs(src)
        self.assertIn(chr(34) + "hello" + chr(34), h[0]["body"])
        self.assertIn("'world'", h[0]["body"])

    def test_heredoc_followed_by_command(self):
        src = "cat <<EOF" + chr(10) + "hello" + chr(10) + "EOF" + chr(10) + "echo done" + chr(10)
        h = scan_heredocs(src)
        self.assertTrue(h[0]["terminated"])
        self.assertEqual(h[0]["body"], "hello")

    def test_crlf_terminator(self):
        src = "cat <<EOF" + chr(13) + chr(10) + "hello" + chr(13) + chr(10) + "EOF" + chr(13) + chr(10)
        h = scan_heredocs(src)
        self.assertTrue(h[0]["terminated"])

    def test_multiple_heredoc_redirects_on_one_line(self):
        src = (
            "cat <<A >f1; cat <<B >f2" + chr(10) +
            "A" + chr(10) + "bodyA" + chr(10) + "A" + chr(10) +
            "B" + chr(10) + "bodyB" + chr(10) + "B" + chr(10)
        )
        h = scan_heredocs(src)
        self.assertEqual(len(h), 2)
        self.assertEqual([x["delimiter"] for x in h], ["A", "B"])


# Protected-region API

class TestProtectedRegion(unittest.TestCase):
    def test_is_inside_heredoc_body(self):
        src = "cat <<EOF" + chr(10) + "line1" + chr(10) + "line2" + chr(10) + "EOF" + chr(10) + "echo outside" + chr(10)
        a = analyze(src)
        self.assertTrue(is_inside_heredoc_body(a, 2))   # line1
        self.assertTrue(is_inside_heredoc_body(a, 3))   # line2
        self.assertFalse(is_inside_heredoc_body(a, 4))  # EOF terminator
        self.assertFalse(is_inside_heredoc_body(a, 5))  # echo outside


# Resource bounds

class TestResourceBounds(unittest.TestCase):
    def test_one_thousand_heredocs(self):
        parts = []
        for i in range(1000):
            d = "END" + str(i)
            parts.append("cat <<" + d + chr(10) + "body" + str(i) + chr(10) + d + chr(10))
        src = chr(10).join(parts)
        h = scan_heredocs(src)
        self.assertEqual(len(h), 1000)
        self.assertTrue(all(x["terminated"] for x in h))


if __name__ == "__main__":
    unittest.main(verbosity=2)
