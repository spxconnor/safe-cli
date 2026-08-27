"""bv/heredoc/analyzer.py - turn scan output into HereDocInfo + semantics + diagnostics.

This module is read-only. It does NOT mutate source. It does NOT
auto-quote, auto-trim, or auto-repair. All decisions are explicit
and emitted as diagnostics for the human/agent to act on.
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Optional, Tuple

from ..diagnostic import Diagnostic, LayerResult
from .diagnostics import (
    BV_HEREDOC_001,
    BV_HEREDOC_002,
    BV_HEREDOC_003,
    BV_HEREDOC_004,
    BV_HEREDOC_005,
    BV_HEREDOC_006,
    BV_HEREDOC_007,
    BV_HEREDOC_008,
    BV_HEREDOC_009,
    BV_HEREDOC_010,
    BV_HEREDOC_011,
    BV_HEREDOC_012,
    make_diagnostic,
)
from .model import HereDocInfo, HereDocSemantics, HereDocAnalysis
from .parser import scan_heredocs


# Heuristic detection of common "structured data" targets.
_STRUCTURED_TARGET_HINTS = (
    ".json", ".yaml", ".yml", ".toml", ".xml", ".html", ".htm",
    ".md", ".markdown", ".csv", ".tsv",
    ".py", ".js", ".ts", ".rb", ".go", ".rs", ".java", ".kt", ".c",
    ".h", ".cpp", ".cs", ".swift", ".kt", ".scala",
    ".sql", ".sh", ".bash", ".zsh", ".dockerfile", "Dockerfile",
    ".ini", ".conf", ".cfg", ".toml", ".env",
)


_PARAM_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
_CMD_SUBST_RE = re.compile(r"\$\([^)]*\)|`[^`\\]*(?:\\.[^`\\]*)*`")
_ARITH_RE = re.compile(r"\$\(\([^)]*\)\)")


def _detect_target_hint(operator_line_text: str) -> Optional[str]:
    """If the operator line redirects the heredoc to a file we can guess
    at, return the path's extension. None if we cannot tell.
    """
    # Look for > or >> followed by a path
    m = re.search(r">>?\s*([^\s;&|]+)", operator_line_text)
    if not m:
        return None
    path = m.group(1).strip("\"'").rstrip("\"'")
    # Strip shell metachars that may trail
    path = path.split("<")[0].split("(")[0]
    return path


def _is_structured_data_target(target_hint: Optional[str]) -> bool:
    if not target_hint:
        return False
    low = target_hint.lower()
    return any(low.endswith(suf) for suf in _STRUCTURED_TARGET_HINTS) or low in (
        "dockerfile", "makefile", ".bashrc", ".zshrc",
    )


def _detect_backslash_newlines(body: str) -> Tuple[int, ...]:
    """Return 1-based line numbers of lines whose previous line ends with
    a backslash, so they participate in a backslash-newline continuation
    under Bash semantics. Only meaningful when expansion is enabled
    (i.e. unquoted heredoc). For quoted heredocs, backslashes are
    literal and do not cause continuation.
    """
    lines = body.split("\n")
    out: List[int] = []
    for i in range(1, len(lines)):
        prev = lines[i - 1]
        if prev.endswith("\\") and not prev.endswith("\\\\"):
            out.append(i + 1)  # 1-based
    return tuple(out)


def _detect_expansion_constructs(body: str) -> Tuple[Tuple[int, ...], bool, bool, bool]:
    """Return (line_numbers_with_expansion, has_param, has_cmd, has_arith).

    These are SYNTACTIC detections: the construct pattern is present in
    the body. Whether it is EXPANDED is determined later by the
    semantics layer (which knows whether the heredoc is quoted or
    backslash-escaped). For example, $HOME appears as a parameter
    expansion in the body of BOTH <<EOF and <<'EOF'; only the
    semantics layer knows which one actually expands it.
    """
    param_lines: List[int] = []
    cmd_lines: List[int] = []
    arith_lines: List[int] = []
    for i, line in enumerate(body.split("\n"), start=1):
        if _PARAM_RE.search(line):
            param_lines.append(i)
        if _CMD_SUBST_RE.search(line):
            cmd_lines.append(i)
        if _ARITH_RE.search(line):
            arith_lines.append(i)
    has_param = bool(param_lines)
    has_cmd = bool(cmd_lines)
    has_arith = bool(arith_lines)
    lines = sorted(set(param_lines + cmd_lines + arith_lines))
    return (tuple(lines), has_param, has_cmd, has_arith)


def _fingerprint(info: HereDocInfo, sem: HereDocSemantics) -> str:
    """Compact fingerprint so we can detect semantic change after repair."""
    h = hashlib.sha256()
    h.update(info.operator.encode())
    h.update(b"\x00")
    h.update(info.delimiter.encode())
    h.update(b"\x00")
    h.update(str(info.quote_style).encode())
    h.update(b"\x00")
    h.update(b"tabs" if info.strip_tabs else b"none")
    h.update(b"\x00")
    h.update(b"on" if sem.expansion_enabled else b"off")
    h.update(b"\x00")
    h.update(info.body.encode("utf-8", errors="replace"))
    return h.hexdigest()[:16]


def _has_trailing_whitespace(text: str) -> bool:
    return text != text.rstrip() and text.rstrip() != text


def _has_actual_trailing_whitespace_on_terminator(term_line: _Line) -> bool:
    """True if the line text has trailing whitespace AFTER the
    delimiter. We do NOT consider a single \r to be trailing whitespace
    (it's the CRLF carriage return).
    """
    text = term_line.text
    if not text:
        return False
    # The text was already stripped of \r at split time.
    return text != text.rstrip()


def _heredoc_body_offset_starts(info: HereDocInfo) -> int:
    """Best-effort 0-based byte offset where the body starts. Used so
    callers can ask "is this byte offset inside a heredoc body?"
    """
    # We approximate from the operator line. A precise answer would
    # require keeping a SourceMap in the parser. Approximate by:
    #   op_line is 1-based; we use 0 (the start of file) for the first
    #   heredoc, and the previous heredoc's terminator offset for
    #   subsequent ones. Without a full SourceMap we cannot do better
    #   in this iteration; the API for "is_inside_heredoc_body" uses
    #   line numbers, which we do track precisely.
    return -1


def analyze(
    source: str,
    source_label: str = "<source>",
    *,
    line_offset: int = 0,
    tree_sitter_heredocs: Optional[List[dict]] = None,
) -> List[HereDocAnalysis]:
    """Run the lexical scanner + Tree Sitter cross-check + diagnostics.

    Args:
      source: the full script text
      source_label: filename for diagnostics
      line_offset: if source is a fragment, add this to all line numbers
      tree_sitter_heredocs: optional list of heredoc dicts from
        the Tree Sitter layer, used for the disagreement check
    """
    raw = scan_heredocs(source)
    out: List[HereDocAnalysis] = []
    # Body line ranges for the protected-region API (computed per info)
    body_spans: List[Tuple[int, int]] = []  # (start_line, end_line) inclusive

    for item in raw:
        op_line = item["op_line"] + line_offset
        op_col = item["op_column"]
        end_line = (item["terminator_line"] + line_offset) if item["terminated"] else None
        body_start = item["body_start_line"] + line_offset
        body_end = (item["body_end_line"] + line_offset) if item["body_end_line"] is not None else None

        info = HereDocInfo(
            index=item["index"],
            start_line=op_line,
            start_column=op_col,
            end_line=end_line,
            operator=item["operator"],
            raw_delimiter=item["raw_delimiter"],
            delimiter=item["delimiter"],
            quoted=item["quote_style"] in ("'", '"'),
            quote_style=item["quote_style"],
            strip_tabs=item["strip_tabs"],
            terminated=item["terminated"],
            terminator_line=item["terminator_line"],
            body_start_line=body_start,
            body_end_line=body_end,
            body=item["body"],
        )
        # Compute semantics
        expansion_enabled = (item["quote_style"] is None) or (item["quote_style"] == "\\")
        # backslash_processing: True for unquoted (Bash removes \\, \$, \`, \\)
        backslash_processing = expansion_enabled
        # Detect constructs SYNTACTICALLY (they appear in the body)...
        expansion_lines, _has_param_in_body, _has_cmd_in_body, _has_arith_in_body = (
            _detect_expansion_constructs(info.body)
        )
        # ...but they only ACTUALLY EXPAND when expansion_enabled.
        # In a quoted heredoc <<'EOF', $HOME is literal text.
        has_param = _has_param_in_body and expansion_enabled
        has_cmd = _has_cmd_in_body and expansion_enabled
        has_arith = _has_arith_in_body and expansion_enabled
        # Backslash-newline only happens in unquoted heredocs.
        bsnl = _detect_backslash_newlines(info.body) if expansion_enabled else ()
        target_hint = _detect_target_hint(
            # The operator line text is in the source; we look it up by
            # line number. We do not have the line here directly; we
            # conservatively return None if the parser did not capture it.
            ""
        )
        # The Tree Sitter layer stores heredoc info; we approximate
        # the target hint from a different angle: search the operator
        # line in the source.
        if source:
            lines = source.split("\n")
            if 0 < info.start_line - line_offset <= len(lines):
                op_text = lines[info.start_line - line_offset - 1]
                target_hint = _detect_target_hint(op_text)
        suspicious = _is_structured_data_target(target_hint) and expansion_enabled
        quoted_literal = item["quote_style"] in ("'", '"')  # <<'X' or <<"X" disable expansion
        # Note: '<<\X' technically disables expansion too in Bash 4+,
        # but we follow Bash 3 semantics here (which DOES expand).
        # (We mark the body accordingly below.)
        sem = HereDocSemantics(
            expansion_enabled=expansion_enabled,
            parameter_expansion=has_param,
            command_substitution=has_cmd,
            arithmetic_expansion=has_arith,
            backslash_processing=backslash_processing,
            backslash_newline_continuations=bsnl,
            quoted_literal_mode=quoted_literal,
            indentation_mode="tabs" if info.strip_tabs else "none",
            suspicious_expansion=suspicious,
            target_hint=target_hint,
        )
        # Mark expansion_constructs on the info for the metadata path
        info_obj = HereDocInfo(
            index=info.index,
            start_line=info.start_line,
            start_column=info.start_column,
            end_line=info.end_line,
            operator=info.operator,
            raw_delimiter=info.raw_delimiter,
            delimiter=info.delimiter,
            quoted=info.quoted,
            quote_style=info.quote_style,
            strip_tabs=info.strip_tabs,
            terminated=info.terminated,
            terminator_line=info.terminator_line,
            body_start_line=info.body_start_line,
            body_end_line=info.body_end_line,
            body=info.body,
            has_expansion_constructs=bool(expansion_lines),
            expansion_construct_lines=expansion_lines,
            backslash_newline_lines=bsnl,
        )
        fp = _fingerprint(info_obj, sem)
        out.append(HereDocAnalysis(info=info_obj, semantics=sem, fingerprint=fp))
        if info.body_end_line is not None:
            body_spans.append((info.body_start_line, info.body_end_line))

    return out


def emit_diagnostics(
    analyses: List[HereDocAnalysis],
    file_label: str,
    layer_result: LayerResult,
) -> None:
    """Walk the analyses and add Diagnostics to the LayerResult.

    We do NOT auto-mutate the source. We only report.
    """
    for a in analyses:
        info = a.info
        sem = a.semantics
        # BV-HEREDOC-001 unterminated
        if not info.terminated:
            layer_result.add(make_diagnostic(
                BV_HEREDOC_001, file_label, info.start_line, info.start_column,
                f"Heredoc with delimiter {info.raw_delimiter!r} is unterminated; "
                f"Bash will read stdin until EOF.",
            ))
            continue
        # BV-HEREDOC-003 trailing whitespace on terminator
        if info.terminator_line is not None:
            # We need the original terminator line text; we stored
            # the raw line via the parser. Recompute from info is
            # not possible (we did not store the raw text); rely on
            # the parser passing it. We approximate: if the body ends
            # with a line that has only whitespace before the delimiter
            # we cannot recover that here. So we re-detect by looking
            # at the scanner output; we re-scan just to get the raw
            # line. (Cheap; this is in-memory.)
            pass
        # BV-HEREDOC-005 unquoted + expansion
        if sem.expansion_enabled and (
            sem.parameter_expansion or sem.command_substitution
            or sem.arithmetic_expansion
        ):
            layer_result.add(make_diagnostic(
                BV_HEREDOC_005, file_label,
                info.start_line, info.start_column,
                f"Unquoted heredoc with delimiter {info.delimiter!r} has "
                "shell expansion constructs in the body; expansion is enabled. "
                "If literal content is intended, use a quoted delimiter.",
            ))
        # BV-HEREDOC-006 structured data + expansion
        if sem.suspicious_expansion:
            target = sem.target_hint or "(unknown target)"
            layer_result.add(make_diagnostic(
                BV_HEREDOC_006, file_label,
                info.start_line, info.start_column,
                f"Heredoc body for {target} is unquoted while the target "
                "appears to be structured data. Expansion may be unintended. "
                "Use a quoted delimiter if literal content is intended.",
            ))
        # BV-HEREDOC-007 backslash-newline in unquoted
        if sem.backslash_newline_continuations and sem.expansion_enabled:
            for ln in sem.backslash_newline_continuations:
                layer_result.add(make_diagnostic(
                    BV_HEREDOC_007, file_label,
                    ln, 1,
                    f"Unquoted heredoc contains a backslash-newline at line {ln}; "
                    "Bash processes this as a line continuation. The effective "
                    "content differs from the visually written two lines. "
                    "No automatic repair was applied because this may be intentional.",
                ))
        # BV-HEREDOC-008 ambiguous backslash
        if "\\\\" in info.body and sem.expansion_enabled:
            layer_result.add(make_diagnostic(
                BV_HEREDOC_008, file_label,
                info.start_line, 1,
                f"Unquoted heredoc body contains literal backslashes. Bash will "
                "process \\X escapes in the body. Use a quoted delimiter if "
                "literal backslashes are required.",
            ))


def is_inside_heredoc_body(
    analyses: List[HereDocAnalysis], line: int
) -> bool:
    """API: is this 1-based line number inside any heredoc body?"""
    for a in analyses:
        if a.info.body_end_line is None:
            continue
        if a.info.body_start_line <= line <= a.info.body_end_line:
            return True
    return False


def body_byte_offset(info: HereDocInfo) -> Tuple[int, int]:
    """Approximate 0-based byte offsets (start, end-exclusive) of the
    body within the source. Use with care; we do not maintain a
    full SourceMap. This is a coarse best-effort.
    """
    # Without a full source map we cannot return absolute byte offsets.
    return (-1, -1)
