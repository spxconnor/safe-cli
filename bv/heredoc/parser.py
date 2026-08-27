"""bv/heredoc/parser.py - line-based heredoc boundary scanner.

Tree Sitter has known open issues with heredoc parsing
(see upstream tree-sitter-bash). For AI-generated Bash, the safe
default is:

  - use Tree Sitter as the preferred structural source
  - independently verify line-based heredoc boundaries
  - if the two disagree, do not silently pick one; emit
    BV-HEREDOC-012 and treat the result as not unconditionally safe

The scanner operates on raw bytes / lines. It does NOT call Bash.
It does NOT execute any user code. It only reads the file.

Strategy:
  1. Walk lines of the source
  2. Identify heredoc operator lines (where `<<` or `<<-` appears in
     a real command position, not in a comment or a quoted string)
  3. From the operator, extract the delimiter and its quote style
  4. Find the matching terminator line:
       - exact match (no leading/trailing whitespace) for `<<`
       - tab-stripped match (leading tabs only) for `<<-`
  5. Capture the body between operator and terminator

This is deliberately conservative: ambiguous or malformed constructs
are reported as errors, not silently normalized.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


# Heredoc operator regex (NOT used alone; the scanner tracks state).
# Two forms: `<<` and `<<-`. We look for these as whole tokens.
_OPERATOR_RE = re.compile(r"<<-?")
# Quoted-delimiter patterns: <<'X', <<"X", <<\X
# The delimiter can contain almost anything Bash considers a valid
# identifier: alnum, _, -, +, /, ., : etc.
_DELIM_RE = re.compile(
    r"""<<-?\s*                              # operator + whitespace
        (?:                                  # one of:
          (\\) (?P<bs_delim>[^\s]+)            #   \X  (backslash-escape)
        | (['"]) (?P<qdelim>[^\s]*) \2        #   'X' or "X" (quoted)
        |       (?P<udelim>[^\s'"\s\\]+)      #   X   (unquoted, no quotes no backslash)
        )""",
    re.VERBOSE,
)


@dataclass
class _Line:
    text: str           # line WITHOUT trailing newline
    raw: bytes          # line as bytes (without the trailing \n)
    has_cr: bool        # True if line ended with \r (CRLF)


def _split_lines_keep_terminator(source: str) -> List[_Line]:
    """Split source into lines without losing CRLF information."""
    out: List[_Line] = []
    # Manual split so we keep the line content WITHOUT the trailing \n
    start = 0
    n = len(source)
    while start < n:
        # Find next \n
        nl = source.find("\n", start)
        if nl < 0:
            text = source[start:]
            has_cr = text.endswith("\r")
            if has_cr:
                text = text[:-1]
            out.append(_Line(text=text, raw=source[start:].encode("utf-8", errors="replace"),
                            has_cr=has_cr))
            break
        text = source[start:nl]
        has_cr = text.endswith("\r")
        if has_cr:
            text = text[:-1]
        out.append(_Line(text=text, raw=source[start:nl + 1].encode("utf-8", errors="replace"),
                        has_cr=has_cr))
        start = nl + 1
    return out


def _is_heredoc_operator_in_real_command_position(line_text: str, op_index: int) -> bool:
    """Best-effort check: is the `<<` operator in a real shell position?

    A more rigorous version would parse the line with Tree Sitter, but
    for the lexical fallback we use simple rules:
      - ignore if preceded by a single-quote (we are inside a '...')
      - ignore if preceded by a double-quote AND no later close on
        the same line (rough heuristic)
      - ignore if inside a # comment (preceded by #, no earlier quote)
    """
    prefix = line_text[:op_index]
    # Count unescaped single quotes; odd => inside a '...'
    sq = 0
    i = 0
    while i < len(prefix):
        c = prefix[i]
        if c == "\\" and i + 1 < len(prefix):
            i += 2
            continue
        if c == "'":
            sq ^= 1
        i += 1
    if sq:
        return False
    # Count unescaped double quotes
    dq = 0
    i = 0
    while i < len(prefix):
        c = prefix[i]
        if c == "\\" and i + 1 < len(prefix):
            i += 2
            continue
        if c == '"':
            dq ^= 1
        i += 1
    if dq:
        return False
    # Comment?
    # If there's a `#` outside any quotes (already confirmed none open),
    # and the `#` is to the LEFT of the operator, the operator is in a comment.
    comment_idx = _find_unquoted_hash(prefix)
    if comment_idx is not None:
        return False
    return True


def _find_unquoted_hash(s: str) -> Optional[int]:
    """Return index of `#` if it starts a real (unquoted) comment in s."""
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            i += 2
            continue
        if c == "#":
            return i
        i += 1
    return None


@dataclass
class _HeredocCandidate:
    op_line_idx: int            # 0-based index into the lines list
    op_column: int              # 0-based column where `<<` starts
    operator: str               # "<<" or "<<-"
    raw_delimiter: str          # what the operator was followed by (with quote/escape)
    delimiter: str              # semantic delimiter
    quote_style: Optional[str]  # "'" | '"' | "\\" or None


def _find_operator_candidates(line: _Line, line_idx: int) -> List[_HeredocCandidate]:
    """Return a list of heredoc operator positions on a single line."""
    text = line.text
    out: List[_HeredocCandidate] = []
    # Naive scan; we look for `<<-?` tokens
    for m in _OPERATOR_RE.finditer(text):
        op = m.group(0)
        end = m.end()
        # Look at what follows
        if end >= len(text):
            continue
        # Skip whitespace
        i = end
        while i < len(text) and text[i] in " \t":
            i += 1
        if i >= len(text):
            continue
        # Now classify the delimiter
        c = text[i]
        if c == "'":
            # <<'X' form
            j = i + 1
            while j < len(text) and text[j] != "'":
                j += 1
            if j >= len(text):
                # Unterminated quoted delimiter; record as best-effort
                raw = text[i:]
                delim = raw[1:]
                out.append(_HeredocCandidate(line_idx, m.start(), op, raw, delim, "'"))
                continue
            delim = text[i + 1:j]
            out.append(_HeredocCandidate(line_idx, m.start(), op, text[i:j + 1],
                                        delim, "'"))
        elif c == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 1
            if j >= len(text):
                raw = text[i:]
                delim = raw[1:]
                out.append(_HeredocCandidate(line_idx, m.start(), op, raw, delim, '"'))
                continue
            delim = text[i + 1:j]
            out.append(_HeredocCandidate(line_idx, m.start(), op, text[i:j + 1],
                                        delim, '"'))
        elif c == "\\":
            # <<\X form
            j = i + 1
            while j < len(text) and not text[j].isspace():
                j += 1
            delim = text[i + 1:j]
            out.append(_HeredocCandidate(line_idx, m.start(), op, text[i:j],
                                        delim, "\\"))
        else:
            # Unquoted delimiter
            j = i
            while j < len(text) and not text[j].isspace():
                j += 1
            delim = text[i:j]
            if delim:
                out.append(_HeredocCandidate(line_idx, m.start(), op, delim,
                                            delim, None))
    return out


def _find_terminator(lines: List[_Line], start_idx: int, delim: str,
                     strip_tabs: bool) -> Tuple[Optional[int], Optional[_Line]]:
    """Find the matching terminator line for `delim`.

    Returns (line_idx, raw_terminator_line). For <<-, leading tabs
    are stripped before comparison. The original line is returned
    for diagnostic reporting.
    """
    for idx in range(start_idx, len(lines)):
        ln = lines[idx]
        text = ln.text
        candidate = text
        if strip_tabs:
            # Strip ONLY leading tabs, not spaces
            stripped = candidate.lstrip("\t")
            tabs_count = len(candidate) - len(stripped)
            candidate = stripped
        else:
            tabs_count = 0
        if candidate == delim:
            return idx, ln
    return None, None


def scan_heredocs(source: str) -> List[dict]:
    """Line-based heredoc scan. Returns a list of plain dicts so the
    caller does not have to import the dataclasses to use the result.

    Each dict has at least:
      op_line, op_column, operator, raw_delimiter, delimiter,
      quote_style, strip_tabs, terminated, terminator_line,
      body_start_line, body_end_line, body
    """
    lines = _split_lines_keep_terminator(source)
    out: List[dict] = []
    index = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        # Find operator candidates in this line
        candidates = _find_operator_candidates(line, i)
        if not candidates:
            i += 1
            continue
        # We may find multiple operators on a single line (rare but legal)
        for cand in candidates:
            # If the candidate is not in a real command position, skip
            if not _is_heredoc_operator_in_real_command_position(line.text, cand.op_column):
                continue
            strip_tabs = cand.operator == "<<-"
            term_idx, term_line = _find_terminator(
                lines, i + 1, cand.delimiter, strip_tabs
            )
            body_start = i + 1
            body_end = (term_idx - 1) if term_idx is not None else None
            if body_end is not None and body_end < body_start:
                # Terminator on the same line as the operator: empty body
                body_end = body_start - 1
            body_text = ""
            if body_end is not None and body_end >= body_start:
                body_text = "\n".join(lines[j].text for j in range(body_start, body_end + 1))
            out.append({
                "index": index,
                "op_line": i + 1,
                "op_column": cand.op_column + 1,  # 1-based for the user
                "operator": cand.operator,
                "raw_delimiter": cand.raw_delimiter,
                "delimiter": cand.delimiter,
                "quote_style": cand.quote_style,
                "strip_tabs": strip_tabs,
                "terminated": term_idx is not None,
                "terminator_line": (term_idx + 1) if term_idx is not None else None,
                "body_start_line": body_start + 1,
                "body_end_line": (body_end + 1) if body_end is not None else None,
                "body": body_text,
            })
            index += 1
        # Advance past the operator line; multiple operators on the
        # same line are all handled in this single iteration.
        i += 1
    return out
