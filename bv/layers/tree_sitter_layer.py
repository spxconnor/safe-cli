"""Layer 1 — Tree-sitter Bash AST analyzer.

Parses the script structurally rather than as plain text and extracts:
  - parse errors (with line/column from the AST)
  - functions, conditionals, loops, pipelines, redirections
  - command substitutions, subshells, expansions
  - heredocs (with quoted/unquoted detection)

This layer is the structural ground truth. If it fails, downstream layers
are skipped until repair.
"""
from __future__ import annotations

from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext


class TreeSitterLayer(Layer):
    name = "tree_sitter"
    description = "Tree-sitter Bash AST parse + structural analysis"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_bash
        except ImportError as e:
            result.status = "skip"
            result.notes.append(f"tree_sitter or tree_sitter_bash not available: {e}")
            return result

        with self._timer():
            try:
                lang = Language(tree_sitter_bash.language(), "bash")
                parser = Parser()
                parser.set_language(lang)
                tree = parser.parse(bytes(script.content, "utf-8"))
            except Exception as e:
                result.status = "error"
                result.add(self._diag(
                    tool="tree_sitter",
                    category=Category.PARSING,
                    severity=Severity.ERROR,
                    message=f"Tree-sitter parse exception: {e}",
                    raw=str(e),
                    repairable=False,
                ))
                result.duration_ms = self._elapsed()
                return result

        root = tree.root_node
        # Collect parse errors
        self._walk_errors(root, script, result)
        # Collect structural info
        meta = {
            "has_errors": root.has_error,
            "function_count": 0,
            "heredoc_count": 0,
            "command_substitution_count": 0,
            "subshell_count": 0,
        }
        self._collect_structure(root, meta)
        result.metadata = meta

        if root.has_error:
            result.status = "fail"
            # Make sure an ERROR diagnostic exists even if walk didn't catch one
            if not any(d.severity == Severity.ERROR for d in result.diagnostics):
                result.add(self._diag(
                    tool="tree_sitter",
                    category=Category.SYNTAX,
                    severity=Severity.ERROR,
                    message="Tree-sitter detected one or more syntax errors in the AST.",
                    suggested_action="fix_syntax",
                ))
        else:
            result.status = "pass"

        result.duration_ms = self._elapsed()
        return result

    def _walk_errors(self, node, script: Script, result: LayerResult) -> None:
        """Recursively find ERROR nodes in the AST."""
        if node.type == "ERROR" or node.is_missing:
            text = node.text.decode("utf-8", errors="replace")[:80]
            result.add(self._diag(
                tool="tree_sitter",
                category=Category.SYNTAX,
                severity=Severity.ERROR,
                file=script.path.as_posix() if script.path else "<stdin>",
                line=node.start_point[0] + 1,
                column=node.start_point[1] + 1,
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1] + 1,
                message=f"Syntax error near: {text!r}",
                code="TS_ERROR",
                raw=node.sexp()[:400],
                suggested_action="fix_syntax",
            ))
        # Also flag unknown / unparsed nodes
        if node.type in ("UNEXPECTED", "missing_node"):
            result.add(self._diag(
                tool="tree_sitter",
                category=Category.PARSING,
                severity=Severity.WARNING,
                file=script.path.as_posix() if script.path else "<stdin>",
                line=node.start_point[0] + 1,
                column=node.start_point[1] + 1,
                message=f"Unexpected token at this position ({node.type})",
                suggested_action="fix_syntax",
            ))
        for child in node.children:
            self._walk_errors(child, script, result)

    def _collect_structure(self, node, meta: dict) -> None:
        """Count structural elements for the metadata report."""
        t = node.type
        if t == "function_definition":
            meta["function_count"] += 1
        elif t in ("heredoc_body", "heredoc_redirect"):
            meta["heredoc_count"] += 1
        elif t == "command_substitution":
            meta["command_substitution_count"] += 1
        elif t == "subshell":
            meta["subshell_count"] += 1
        # Recurse
        for child in node.children:
            self._collect_structure(child, meta)

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        d = diagnostic_from_message(layer=self.name, **kwargs)
        return d
