"""bv/quoting/nested_lang.py — nested-language detector.

When Bash is the outer parser but the inner command runs in a DIFFERENT
language (Python, awk, jq, sed, ssh-remote-bash, sql, json, etc.) we are
facing a CROSS-LANGUAGE quoting boundary. Each inner language has its
own quoting rules; blindly escaping more characters at the outer level
will eventually corrupt both layers.

This module detects these boundaries and reports them as evidence to
the quoting analyzer. It does NOT modify the user's source. It just
records:

    - the outer command (e.g. ssh)
    - the inner language (e.g. remote bash)
    - the source span that contains the cross-language region
    - the structural confidence in the detection

The repair engine consults this evidence to refuse naive quoting-only
fixes and prefer structural restructuring (use heredocs, temp files,
argument arrays, etc.) when the cross-language risk is high.

DESIGN PRINCIPLE (spec section 28):
    When complexity becomes too high for safe deterministic repair:
        - DO NOT blindly escape more characters.
        - DO NOT add random backslashes.
        - DO NOT keep nesting shell quotes indefinitely.
        - Instead prefer: temp files, stdin, env vars, quoted heredocs,
          direct subprocess invocation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .model import ContextKind, ShellWord


# ---------------------------------------------------------------------------
# Cross-language detector registry
# ---------------------------------------------------------------------------


# A boundary is a tuple:
#   (outer_command_prefix, outer_arg_pattern, inner_language, risk)
# where outer_command_prefix matches the first word of the command, and
# outer_arg_pattern matches a positional argument that contains code in
# `inner_language`.  We deliberately use small allowlists rather than
# over-broad heuristics.
#
# risk is one of: "low", "medium", "high"
#   low      : the inner language shares most of Bash's quoting rules
#   medium   : the inner language has DIFFERENT quoting rules but no
#              recursion through another shell
#   high     : the inner language either recurses through another shell
#              (e.g. ssh -> bash) or has a fully different escape grammar
#              (e.g. jq strings with backslash rules distinct from Bash)
_NESTED_BOUNDARIES: List[Tuple[str, str, str, str]] = [
    # Bash -> SSH -> Bash
    ("ssh", "bash -c", "remote_bash", "high"),
    ("ssh", "sh -c", "remote_sh", "high"),
    ("ssh", "bash", "remote_bash", "high"),
    ("scp", "*", "scp_path", "medium"),
    ("rsync", "*", "rsync_path", "medium"),

    # Bash -> shell-out
    ("bash", "-c", "child_bash", "medium"),
    ("sh", "-c", "child_sh", "medium"),
    ("dash", "-c", "child_sh", "medium"),
    ("env", "-i", "child_env", "medium"),
    ("xargs", "*", "xargs_split", "medium"),
    ("parallel", "*", "parallel_args", "medium"),

    # Bash -> text-processing DSLs
    ("awk", "*", "awk", "high"),
    ("gawk", "*", "awk", "high"),
    ("mawk", "*", "awk", "high"),
    ("sed", "*", "sed_expr", "high"),
    ("perl", "-e", "perl", "high"),
    ("perl", "-pe", "perl", "high"),

    # Bash -> JSON tools
    ("jq", "*", "jq_program", "high"),
    ("jq", "-f", "jq_program_file", "high"),

    # Bash -> Python / Ruby / Node
    ("python", "-c", "python", "high"),
    ("python2", "-c", "python", "high"),
    ("python3", "-c", "python", "high"),
    ("ruby", "-e", "ruby", "high"),
    ("node", "-e", "node", "high"),
    ("node", "-p", "node", "high"),
    ("deno", "eval", "deno", "high"),
    ("php", "-r", "php", "high"),

    # Bash -> SQL
    ("psql", "-c", "sql", "high"),
    ("mysql", "-e", "sql", "high"),
    ("sqlite3", "*", "sql", "high"),
    ("pg_dump", "*", "sql_text", "medium"),

    # Bash -> Make
    ("make", "-e", "make", "medium"),

    # Bash -> find with -exec
    ("find", "-exec", "find_exec", "medium"),
]


@dataclass(frozen=True)
class NestedBoundary:
    """One detected cross-language boundary."""
    outer_command: str         # e.g. "ssh"
    inner_language: str        # e.g. "remote_bash"
    risk: str                  # 'low' | 'medium' | 'high'
    span: Tuple[int, int]      # byte offsets in source
    description: str


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _shell_words_for_command(words: Sequence[ShellWord]) -> List[ShellWord]:
    """Return just the words that belong to a single command invocation."""
    return [w for w in words if w.context_kind in (ContextKind.COMMAND_NAME, ContextKind.COMMAND_ARG)]


def detect_boundaries(words: Sequence[ShellWord]) -> List[NestedBoundary]:
    """Walk the shell words and detect any cross-language boundaries.

    Returns a list of NestedBoundary records. Empty list means no
    cross-language nesting was detected.
    """
    out: List[NestedBoundary] = []
    if not words:
        return out

    # We use a sliding 2-word window: command name + first argument
    # (where most -c / -e arguments live) plus lookups of -f / -exec.
    cmd_name: Optional[str] = None
    cmd_name_start: Optional[int] = None
    for w in words:
        if w.context_kind == ContextKind.COMMAND_NAME:
            cmd_name = w.raw_text
            cmd_name_start = w.start_byte
        elif w.context_kind == ContextKind.COMMAND_ARG and cmd_name:
            cmd = cmd_name.strip()
            arg = w.raw_text.strip()
            for outer_prefix, arg_pattern, inner_lang, risk in _NESTED_BOUNDARIES:
                if cmd != outer_prefix and not cmd.startswith(outer_prefix):
                    continue
                if arg_pattern == "*":
                    matched = True
                elif arg_pattern == "-c":
                    matched = arg in ("-c", '"-c"')
                elif arg_pattern == "-e":
                    matched = arg in ("-e",)
                elif arg_pattern == "-r":
                    matched = arg in ("-r",)
                elif arg_pattern == "-p":
                    matched = arg in ("-p",)
                elif arg_pattern == "-f":
                    matched = arg in ("-f",)
                elif arg_pattern == "-i":
                    matched = arg in ("-i",)
                elif arg_pattern == "-pe":
                    matched = arg in ("-pe",)
                elif arg_pattern == "bash -c":
                    matched = arg in ("bash", '"bash"') and len(words) > 0
                elif arg_pattern == "sh -c":
                    matched = arg in ("sh", '"sh"')
                elif arg_pattern == "bash":
                    matched = arg == "bash"
                elif arg_pattern == "-exec":
                    matched = arg == "-exec"
                else:
                    matched = False
                if matched:
                    out.append(
                        NestedBoundary(
                            outer_command=cmd,
                            inner_language=inner_lang,
                            risk=risk,
                            span=(w.start_byte, w.end_byte),
                            description=(
                                f"cross-language boundary: Bash -> {cmd} -> "
                                f"{inner_lang} ({risk} risk)"
                            ),
                        )
                    )
                    break
        # Reset on operator words? We don't because some commands span
        # line continuations; that's a known limitation.
    return out


def find_max_risk(boundaries: Sequence[NestedBoundary]) -> str:
    """Return the maximum risk level across all detected boundaries."""
    levels = {"low": 0, "medium": 1, "high": 2}
    best = "low"
    for b in boundaries:
        if levels.get(b.risk, 0) > levels[best]:
            best = b.risk
    return best


def is_quoting_hell(boundaries: Sequence[NestedBoundary]) -> bool:
    """True when the cross-language complexity exceeds safe deterministic repair.

    Spec section 28:
      When complexity becomes too high for safe deterministic repair:
        - DO NOT blindly escape more characters.
        - DO NOT add random backslashes.
        - DO NOT keep nesting shell quotes indefinitely.
        - Instead prefer restructuring.
    """
    if not boundaries:
        return False
    if find_max_risk(boundaries) == "high":
        # High risk means we either recurse through another shell OR
        # use a fully different escape grammar. Both warrant refusal.
        return True
    return False
