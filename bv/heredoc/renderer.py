"""bv/heredoc/renderer.py - human-friendly explanation of a heredoc analysis."""
from __future__ import annotations

from typing import List

from .model import HereDocAnalysis


def render_one(a: HereDocAnalysis) -> str:
    info = a.info
    sem = a.semantics
    qs = {
        None: "unquoted",
        "'": "single-quoted",
        '"': "double-quoted",
        "\\": "backslash-escaped",
    }.get(info.quote_style, repr(info.quote_style))
    body_status = "valid" if info.terminated else "UNTERMINATED"
    expansion = "enabled" if sem.expansion_enabled else "disabled (literal)"
    backslash = "enabled" if sem.backslash_processing else "literal"
    indent = "tabs (<<-)" if info.strip_tabs else "none (exact match required)"
    out: List[str] = []
    out.append(f"HEREDOC #{info.index + 1}")
    out.append(f"  operator line   : {info.start_line}")
    out.append(f"  operator column : {info.start_column}")
    out.append(f"  operator        : {info.operator}")
    out.append(f"  raw delimiter   : {info.raw_delimiter!r}")
    out.append(f"  semantic delim  : {info.delimiter!r}")
    out.append(f"  delimiter style : {qs}")
    out.append(f"  expansion       : {expansion}")
    out.append(f"  backslash proc  : {backslash}")
    out.append(f"  indentation     : {indent}")
    out.append(f"  body range      : {info.body_start_line}-{info.body_end_line}")
    out.append(f"  terminator      : {info.terminator_line}")
    out.append(f"  status          : {body_status}")
    if sem.parameter_expansion or sem.command_substitution or sem.arithmetic_expansion:
        out.append(f"  constructs      : "
                   f"param={sem.parameter_expansion} "
                   f"cmdsub={sem.command_substitution} "
                   f"arith={sem.arithmetic_expansion}")
    if sem.backslash_newline_continuations:
        out.append(f"  backslash-newline lines: {list(sem.backslash_newline_continuations)}")
    if sem.suspicious_expansion:
        out.append(f"  WARNING: target appears to be structured data; expansion may be unintended")
    if a.parser_disagreement:
        out.append(f"  PARSER DISAGREEMENT: {a.parser_disagreement_kind}")
    return "\n".join(out)


def render_all(analyses: List[HereDocAnalysis]) -> str:
    if not analyses:
        return "No heredocs found."
    return "\n\n".join(render_one(a) for a in analyses)
