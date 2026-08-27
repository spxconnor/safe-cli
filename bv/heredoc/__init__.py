"""bv/heredoc/ - first-class heredoc semantic analysis for safe-cli.

This package is the production-grade, conservative heredoc engine.

The invariant:

  Structural understanding  : Tree Sitter (preferred)
  Line-based fallback       : bv.heredoc.parser (always)
  Semantic interpretation   : bv.heredoc.analyzer (read-only)
  Decision policy           : bv.heredoc.diagnostics (rule IDs)
  Human output              : bv.heredoc.renderer

It NEVER auto-quotes, auto-trims, or auto-modifies heredoc bodies.
All decisions are explicit diagnostics for the human or agent.
"""
from .model import HereDocAnalysis, HereDocInfo, HereDocSemantics
from .analyzer import analyze, emit_diagnostics, is_inside_heredoc_body
from .parser import scan_heredocs
from .diagnostics import make_diagnostic
from .renderer import render_one, render_all


__all__ = [
    "HereDocInfo",
    "HereDocSemantics",
    "HereDocAnalysis",
    "scan_heredocs",
    "analyze",
    "emit_diagnostics",
    "is_inside_heredoc_body",
    "make_diagnostic",
    "render_one",
    "render_all",
]
