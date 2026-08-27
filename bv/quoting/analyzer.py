"""bv/quoting/analyzer.py - structural shell-word analyzer.

This module scans a Bash source string and produces a list of
ShellWord objects (see model.py) describing every interesting shell
word we want to consider for quoting analysis.

DESIGN CONSTRAINTS:
  - Read-only. Never mutates source.
  - Conservative. If we cannot classify a word safely, we skip it
    rather than produce a noisy / wrong finding.
  - Heredoc-aware. Heredoc bodies are protected lexical regions and
    are NOT scanned as ordinary command arguments. We cooperate with
    bv.heredoc.parser.scan_heredocs() to discover those regions.
  - Source-span based. Every ShellWord carries exact byte offsets.
  - Crash-resistant. We never raise on malformed input; we just
    produce a (possibly empty) word list and let the caller decide.

We deliberately use a hand-written tokenizer rather than Tree-sitter:
  - Tree-sitter may not be installed in every CI / sandbox / repair
    context.
  - The quoting subsystem must remain usable in degraded mode.
  - Tree-sitter findings, when available, arrive via the existing
    tree_sitter_layer and can be merged into our findings in
    bv.quoting.rules via ShellCheck-SC2086 mapping. We do not block
    on it.

The tokenizer is a single forward scan that:
  1. Skips comments.
  2. Tracks quote state (none / single / double / ansi_c / command-subst / arith).
  3. Tracks heredoc bodies as protected regions.
  4. Recognizes assignment vs command contexts.
  5. Records expansions inside each word (parameter, command-subst, arithmetic).
  6. Recognizes ``[[ ]]`` vs ``[ ]`` and assignment contexts.

The output is a flat list of ShellWord. The caller decides how to
group them or which to analyze further.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .model import (
    ContextKind,
    Expansion,
    Intent,
    QuoteType,
    SemanticFlags,
    ShellWord,
)


# ---------------------------------------------------------------------------
# Heredoc region discovery
# ---------------------------------------------------------------------------


def _heredoc_protected_offsets(source: str) -> Set[int]:
    """Return the set of byte offsets that fall inside any heredoc BODY.

    We use bv.heredoc.parser.scan_heredocs if it is available; otherwise
    we fall back to a small regex that catches the common cases. Either
    way we MUST return a set so the main tokenizer can skip those bytes.

    The bv.heredoc.parser.scan_heredocs API returns DICTIONARIES with
    line-numbered start/end (`body_start_line`, `body_end_line`), NOT
    byte offsets. We therefore walk the source to translate.
    """
    protected: Set[int] = set()

    # Pre-compute the byte offset of the start of each line, 1-based.
    line_starts: List[int] = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            line_starts.append(i + 1)

    def line_to_offset(ln: int) -> int:
        # 1-based line number -> 0-based byte offset of line start
        if ln < 1:
            return 0
        if ln - 1 < len(line_starts):
            return line_starts[ln - 1]
        return len(source)

    def offset_end_of_line(ln: int) -> int:
        if ln - 1 < len(line_starts) - 1:
            # end of line ln = start of line ln+1 - 1
            return line_starts[ln] - 1
        return len(source)

    try:
        from ..heredoc.parser import scan_heredocs  # type: ignore
        for info in scan_heredocs(source):
            # The parser may return either an object with attributes or
            # a dict; support both.
            def _get(key: str, attr: str):
                if isinstance(info, dict):
                    return info.get(key)
                return getattr(info, attr, None)

            body_start_line = _get("body_start_line", "body_start_line")
            body_end_line = _get("body_end_line", "body_end_line")
            if body_start_line is None or body_end_line is None:
                continue
            start = line_to_offset(body_start_line)
            end = offset_end_of_line(body_end_line)
            for off in range(start, end):
                protected.add(off)
    except Exception:
        # Fallback: only catch the simplest <<EOF / <<'EOF' / <<\EOF cases.
        pattern = re.compile(
            r"<<-?\s*(?:(['\"])|\\)([A-Za-z_][A-Za-z0-9_]*)\1|<<-?\s*([A-Za-z_][A-Za-z0-9_]*)"
        )
        for m in pattern.finditer(source):
            tag = m.group(2) or m.group(3)
            if not tag:
                continue
            body_start = m.end()
            nl = source.find("\n", body_start)
            if nl < 0:
                continue
            line_start = nl + 1
            lines = source[line_start:].split("\n")
            cursor = line_start
            for line in lines:
                stripped = line.lstrip(" \t")
                if stripped == tag or stripped.startswith(tag + "\n"):
                    for off in range(cursor, cursor + len(line)):
                        protected.add(off)
                    break
                cursor += len(line) + 1
    return protected


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


# Tokens we treat as interesting inside a shell word.
_PARAM_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
_CMD_SUBST_DOLLAR_RE = re.compile(r"\$\(")
_CMD_SUBST_BACKTICK_RE = re.compile(r"`")
_ARITH_RE = re.compile(r"\$\(\(")
_TILDE_RE = re.compile(r"(^|[\s=:])(~)(?:\+|-)?(?:/|$)")

# Simple command name detection: an unquoted bare word followed by whitespace
# and then at least one more token. We use this only as a hint for context.
_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")

# Recognized "command-ish" names that the engine treats specially for
# heuristic command semantics (separate from quoting rules themselves).
# This is a closed allowlist; we never silently extend it at runtime.
_COMMAND_HINTS = frozenset({
    "rm", "mv", "cp", "cat", "mkdir", "rmdir", "ln", "chmod", "chown",
    "echo", "printf", "cd", "pushd", "popd",
    "grep", "egrep", "fgrep", "sed", "awk",
    "find", "xargs",
    "tar", "rsync", "ssh", "scp", "curl", "wget", "git",
    "eval", "exec", "source", ".",
    "test", "[", "[[",
})


def _classify_quote_state(s: str) -> QuoteType:
    """Very coarse quote classification for a single word."""
    if not s:
        return QuoteType.NONE
    # All single-quoted and the content has no expansion -> SINGLE
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return QuoteType.SINGLE
    # All double-quoted
    if s.startswith('"') and s.endswith('"') and len(s) >= 2 and "'" not in s[1:-1]:
        return QuoteType.DOUBLE
    # $'...' ANSI C
    if s.startswith("$'") and s.endswith("'") and len(s) >= 3:
        return QuoteType.ANSI_C
    if '"' in s or "'" in s:
        return QuoteType.PARTIAL
    return QuoteType.NONE


def _has_unescaped_dollar_param(s: str) -> bool:
    """True if `s` contains a $VAR / ${VAR} that is NOT inside single quotes."""
    # Strip single-quoted spans.
    cleaned = re.sub(r"'[^']*'", "", s)
    return bool(_PARAM_RE.search(cleaned))


def _has_unescaped_command_subst(s: str) -> bool:
    cleaned = re.sub(r"'[^']*'", "", s)
    return bool(_CMD_SUBST_DOLLAR_RE.search(cleaned) or _CMD_SUBST_BACKTICK_RE.search(cleaned))


def _has_unescaped_arith(s: str) -> bool:
    cleaned = re.sub(r"'[^']*'", "", s)
    return bool(_ARITH_RE.search(cleaned))


def _has_unescaped_tilde(s: str) -> bool:
    cleaned = re.sub(r"'[^']*'", "", s)
    return bool(_TILDE_RE.search(cleaned))


def _has_escape(s: str) -> bool:
    return "\\" in s and bool(re.search(r"\\[^\n]", s))


def _line_col(source: str, byte_offset: int) -> Tuple[int, int]:
    """Return 1-based (line, column) for the given byte offset."""
    if byte_offset < 0:
        return 1, 1
    head = source[:byte_offset]
    nl = head.rfind("\n")
    if nl < 0:
        return 1, byte_offset + 1
    return head.count("\n") + 1, byte_offset - nl


def _expand_spans(source: str, words: Iterable[Tuple[int, int, str, ContextKind, Optional[str], Optional[int]]]) -> List[ShellWord]:
    """Convert (start, end, raw, context, command_name, arg_position) tuples into ShellWord objects."""
    out: List[ShellWord] = []
    for start, end, raw, ctx, cmd_name, arg_pos in words:
        quote_type = _classify_quote_state(raw)
        # expansions - we record each $VAR / $(...) occurrence
        expansions: List[Expansion] = []
        cleaned = re.sub(r"'[^']*'", "", raw)
        for m in _PARAM_RE.finditer(cleaned):
            tok = m.group(0)
            # Extract the variable name from $VAR or ${VAR}
            if tok.startswith("${") and tok.endswith("}"):
                name = tok[2:-1]
            else:
                name = tok[1:]
            expansions.append(
                Expansion(kind="parameter", raw=tok, start=start + m.start(), end=start + m.end(), name=name)
            )
        for m in _CMD_SUBST_DOLLAR_RE.finditer(cleaned):
            # Walk forward to find the matching ')' for nested $().
            depth = 1
            i = m.end()
            while i < len(cleaned) and depth > 0:
                if cleaned[i] == "(":
                    depth += 1
                elif cleaned[i] == ")":
                    depth -= 1
                i += 1
            expansions.append(
                Expansion(kind="command_substitution", raw=cleaned[m.start():i], start=start + m.start(), end=start + i)
            )
        for m in _ARITH_RE.finditer(cleaned):
            depth = 2  # we already saw $(
            i = m.end()
            while i < len(cleaned) and depth > 0:
                if cleaned[i] == "(":
                    depth += 1
                elif cleaned[i] == ")":
                    depth -= 1
                i += 1
            expansions.append(
                Expansion(kind="arithmetic", raw=cleaned[m.start():i], start=start + m.start(), end=start + i)
            )

        sem = SemanticFlags(
            parameter_expansion=bool(_has_unescaped_dollar_param(raw)),
            command_substitution=bool(_has_unescaped_command_subst(raw)),
            arithmetic_expansion=bool(_has_unescaped_arith(raw)),
            tilde_expansion=bool(_has_unescaped_tilde(raw)),
            # word splitting / pathname expansion / empty disappearance are
            # possible ONLY for unquoted expansions
            word_splitting_possible=(quote_type in (QuoteType.NONE, QuoteType.PARTIAL)
                                     and (_has_unescaped_dollar_param(raw) or _has_unescaped_command_subst(raw))),
            pathname_expansion_possible=(quote_type in (QuoteType.NONE, QuoteType.PARTIAL)),
            empty_value_can_disappear=(quote_type in (QuoteType.NONE, QuoteType.PARTIAL)
                                       and (_has_unescaped_dollar_param(raw) or _has_unescaped_command_subst(raw))),
            quote_removal_possible=True,
        )

        line, col = _line_col(source, start)
        out.append(
            ShellWord(
                start_byte=start,
                end_byte=end,
                start_line=line,
                start_column=col,
                raw_text=raw,
                quote_type=quote_type,
                has_parameter_expansion=sem.parameter_expansion,
                has_command_substitution=sem.command_substitution,
                has_arithmetic_expansion=sem.arithmetic_expansion,
                has_tilde_expansion=sem.tilde_expansion,
                has_escaped_characters=_has_escape(raw),
                expansions=tuple(expansions),
                context_kind=ctx,
                command_name=cmd_name,
                argument_position=arg_pos,
                is_in_test=ctx in (ContextKind.TEST_BRACKET, ContextKind.TEST_DOUBLE_BRACKET),
                is_in_conditional=False,
                is_in_array=False,
                is_in_heredoc_body=(ctx == ContextKind.HERE_DOC_BODY),
                semantic=sem,
                intent=Intent.UNKNOWN,
                intent_confidence=0.0,
                intent_evidence=(),
                user_controlled=False,
            )
        )
    return out


def _offset_outside_heredoc(off: int, protected: Set[int]) -> bool:
    """Linear bound check is fine because we do not read protected bytes."""
    return off not in protected


# ---------------------------------------------------------------------------
# Forward tokenizer
# ---------------------------------------------------------------------------


def analyze(source: str) -> List[ShellWord]:
    """Return a list of ShellWord for the given Bash source string.

    The list may be empty. The caller is responsible for filtering
    further (e.g. dropping words that do not contain expansions).
    """
    if not source:
        return []
    protected = _heredoc_protected_offsets(source)
    n = len(source)

    raw_words: List[Tuple[int, int, str, ContextKind, Optional[str], Optional[int]]] = []

    i = 0
    line_no = 1
    pending_command: Optional[str] = None
    pending_arg_position: int = 0
    in_double_bracket = False
    in_single_bracket = False
    in_arith = False
    in_assignment_prefix = False  # VAR= context
    assignment_target: Optional[str] = None
    export_like = False  # export / readonly / local / declare / typeset

    def is_word_char(c: str) -> bool:
        return c.isalnum() or c in "_-"

    def skip_to_word_end(start: int) -> int:
        j = start
        while j < n:
            c = source[j]
            if c == "\\" and j + 1 < n:
                j += 2
                continue
            if c in ("'", '"'):
                quote = c
                j += 1
                while j < n and source[j] != quote:
                    if source[j] == "\\" and j + 1 < n:
                        j += 2
                    else:
                        j += 1
                if j < n:
                    j += 1
                continue
            if c in " \t\n;&|<>()":
                break
            j += 1
        return j

    while i < n:
        c = source[i]

        # skip heredoc-protected regions entirely
        if i in protected:
            i += 1
            continue

        # newline
        if c == "\n":
            line_no += 1
            pending_command = None
            pending_arg_position = 0
            i += 1
            continue

        # whitespace
        if c in " \t":
            i += 1
            continue

        # comment
        if c == "#":
            while i < n and source[i] != "\n":
                i += 1
            continue

        # compound operators that reset command/arg tracking
        if c in (";", "&", "|", "(", ")"):
            if c == "(":
                # start of subshell; we don't analyze inside subshells
                # specially — just reset command/arg state
                pass
            if c == ";" or c == "&" or c == "|":
                pending_command = None
                pending_arg_position = 0
            if c == ")":
                # closing paren ends subshell/case — keep state minimal
                pass
            i += 1
            continue

        # detect `[[` and `]]`
        if c == "[" and source[i:i + 2] == "[[":
            in_double_bracket = True
            i += 2
            continue
        if c == "]" and source[i:i + 2] == "]]":
            in_double_bracket = False
            i += 2
            continue

        # detect `[` (test)
        if c == "[" and (i + 1 >= n or source[i + 1] != "["):
            in_single_bracket = True
            # do not consume; let the regular word logic pick it up
            # but we want to mark context for what follows
            i += 1
            continue
        if c == "]" and not in_double_bracket:
            in_single_bracket = False
            i += 1
            continue

        # detect assignment prefix at start of word: VAR=...
        # We look ahead only a few characters; if it really is an
        # assignment we consume VAR as the assignment target.
        assignment_target_this_word: Optional[str] = None
        if c.isalpha() or c == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            if j < n and source[j] == "=" and (j + 1 >= n or source[j + 1] != "="):
                # Possibly an assignment.
                # But not if previous token indicates command context like
                # `cmd VAR=...` — those are env-style prefixes, not assignments.
                # We treat them conservatively as command arg.
                if pending_command is None or pending_command in ("export", "readonly", "local", "declare", "typeset"):
                    assignment_target_this_word = source[i:j]
                    if pending_command in ("export", "readonly", "local", "declare", "typeset"):
                        export_like = True
                        i = j + 1  # skip past '='
                    else:
                        i = j + 1
                    # continue to read the RHS word below
                else:
                    assignment_target_this_word = None

        # word boundary
        word_start = i
        word_end = skip_to_word_end(i)
        raw = source[word_start:word_end]

        # Skip if empty
        if not raw:
            i = word_end + 1
            continue

        # Classify context
        if in_double_bracket:
            ctx = ContextKind.TEST_DOUBLE_BRACKET
        elif in_single_bracket:
            ctx = ContextKind.TEST_BRACKET
        elif assignment_target_this_word is not None and not export_like:
            ctx = ContextKind.ASSIGNMENT
        elif export_like and assignment_target_this_word is not None:
            if pending_command == "export":
                ctx = ContextKind.EXPORT_VALUE
            elif pending_command in ("local",):
                ctx = ContextKind.LOCAL_VALUE
            elif pending_command in ("declare", "typeset"):
                ctx = ContextKind.DECLARE_VALUE
            else:
                ctx = ContextKind.ASSIGNMENT
        elif raw.startswith(">"):
            ctx = ContextKind.REDIRECT_TARGET
        elif raw.startswith("<"):
            ctx = ContextKind.REDIRECT_SOURCE
        else:
            ctx = ContextKind.COMMAND_ARG if pending_command else ContextKind.COMMAND_NAME

        # Compute argument position for command args
        arg_pos: Optional[int] = None
        cmd_name_for_word: Optional[str] = None
        if ctx == ContextKind.COMMAND_NAME:
            pending_command = raw
            pending_arg_position = 0
            arg_pos = 0
            cmd_name_for_word = None
            if pending_command not in _COMMAND_HINTS:
                # We still record it; rules.py uses heuristics over the
                # command name but does not require it to be in the list.
                pass
        elif ctx in (ContextKind.COMMAND_ARG, ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE):
            pending_arg_position += 1
            arg_pos = pending_arg_position
            cmd_name_for_word = pending_command
        else:
            cmd_name_for_word = pending_command
            arg_pos = None

        raw_words.append((word_start, word_end, raw, ctx, cmd_name_for_word, arg_pos))

        # Reset export-like on next word boundary
        export_like = False

        # advance
        i = word_end
        if i < n and source[i] in " \t\n;":
            i += 1

    return _expand_spans(source, raw_words)


def filter_words_with_unsafe_expansions(words: Sequence[ShellWord]) -> List[ShellWord]:
    """Return only words whose unquoted expansions could be unsafe.

    A word is "interesting" for quoting analysis if:
      - it has an unquoted parameter expansion AND
        it is NOT already inside matching double quotes, AND
        it is not already a literal single-quoted span, AND
        it is not inside a heredoc body (those are protected regions).
    """
    out: List[ShellWord] = []
    for w in words:
        if w.is_in_heredoc_body:
            continue
        if w.quote_type in (QuoteType.SINGLE,):
            continue
        has_expansion = (
            w.has_parameter_expansion
            or w.has_command_substitution
            or w.has_arithmetic_expansion
        )
        if not has_expansion:
            continue
        # Already wrapped in matching double quotes -> safe
        if w.quote_type == QuoteType.DOUBLE:
            continue
        out.append(w)
    return out
