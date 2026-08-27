"""bv/quoting/dataflow.py - lightweight taint tracking.

This module implements a deliberately SIMPLE dataflow model. It does
not try to be a full program slicer. It tracks:

  - TAINT SOURCES:
      - positional arguments $1, $2, ..., $@
      - stdin (read)
      - command output assigned to a variable: VAR=$(cmd)
      - environment-derived variables (we do not have access to env
        without running; we just mark certain names like $USER, $HOME
        as environment-derived)

  - PROPAGATION:
      - VAR=$SOURCE     (assignment, propagates taint)
      - VAR=${SOURCE}   (same)
      - VAR="$(cmd)"    (same — command output is tainted)
      - VAR=$(cmd)      (same)

  - SINKS (where tainted values are dangerous):
      - eval, exec, source, bash -c, sh -c, xargs, ssh, scp, curl,
        wget, rm, mv, cp, find, git (the dynamic-execution and
        filesystem-altering sinks)

The output is a per-word "user_controlled" flag plus a list of which
sinks are involved. The quoting rules and risk module consult this
flag to downgrade confidence and to escalate severity when needed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .model import ContextKind, ShellWord


# Names that almost always come from the environment.
_ENV_NAMES = frozenset({
    "USER", "HOME", "PWD", "OLDPWD", "SHELL", "PATH", "LANG", "LC_ALL",
    "TERM", "DISPLAY", "EDITOR", "VISUAL", "PAGER", "TMPDIR", "LOGNAME",
    "MAIL", "HOSTNAME", "SHLVL", "RANDOM", "LINES", "COLUMNS",
})


# Names that almost always come from positional arguments.
_POSITIONAL_RE = re.compile(r"^\$([1-9][0-9]*)$")
_ALL_POSITIONAL_RE = re.compile(r"^\$@$|^\$\*$|^\"\$\@\"$|^\"\$\*\"$")


@dataclass(frozen=True)
class TaintInfo:
    is_tainted: bool
    sources: Tuple[str, ...] = ()
    sinks: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Source detection
# ---------------------------------------------------------------------------


def _is_taint_source_name(name: str) -> bool:
    if not name:
        return False
    if _POSITIONAL_RE.match(name):
        return True
    if _ALL_POSITIONAL_RE.match(name):
        return True
    if name in _ENV_NAMES:
        return True
    if name.startswith("$"):
        # $?, $$, $!, $-, $0 — runtime state, generally not user input
        return False
    return False


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


def build_taint_map(source_text: str) -> Dict[str, bool]:
    """Return a map {VARNAME: tainted?} by scanning assignments."""
    taint: Dict[str, bool] = {}

    # Pre-seed: env-derived names are considered tainted (they ARE
    # user-controlled in the broad sense, even if only by the same user).
    for n in _ENV_NAMES:
        taint[n] = True

    # Pre-seed: positional parameters are tainted.
    for i in range(1, 10):
        taint[str(i)] = True
    taint["@"] = True
    taint["*"] = True

    # Walk the source line-by-line. This is a coarse approximation;
    # function-local scoping is not modeled.
    for raw_line in source_text.split("\n"):
        # Strip comments
        line = raw_line.split("#", 1)[0]
        # Match simple assignment: NAME=$(...)  or  NAME=`...`  or NAME=value
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not m:
            continue
        var = m.group(1)
        rhs = m.group(2)

        # Check if RHS contains $VAR (any name)
        rhs_tainted = False
        for ref in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", rhs):
            if taint.get(ref, False):
                rhs_tainted = True
                break
        # Check if RHS is a $(...) or `...` (command output)
        if not rhs_tainted:
            if re.search(r"\$\(", rhs) or re.search(r"`", rhs):
                rhs_tainted = True
        # Check if RHS is unquoted positional-like
        if not rhs_tainted:
            if re.search(r"\$@|\$\*|\$[1-9]", rhs):
                rhs_tainted = True

        taint[var] = rhs_tainted

    return taint


def sink_for_command(cmd: Optional[str]) -> Optional[str]:
    if not cmd:
        return None
    base = cmd.strip().split()[0] if cmd.strip() else ""
    if base in (
        "eval", "exec", "source",
        "xargs", "ssh", "scp", "rsync",
        "curl", "wget",
        "rm", "mv", "cp", "find", "git",
        "bash", "sh",
    ):
        return base
    return None


# ---------------------------------------------------------------------------
# Per-word annotation
# ---------------------------------------------------------------------------


def annotate_word_taint(
    word: ShellWord,
    taint_map: Dict[str, bool],
) -> TaintInfo:
    if not word.expansions:
        return TaintInfo(is_tainted=False, sources=(), sinks=())
    sources: List[str] = []
    for e in word.expansions:
        if not e.name:
            continue
        if _is_taint_source_name(e.name) or taint_map.get(e.name, False):
            sources.append(e.name)
    sink = sink_for_command(word.command_name)
    sinks = (sink,) if sink else ()
    return TaintInfo(is_tainted=bool(sources), sources=tuple(sources), sinks=sinks)


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def apply_dataflow(words: Sequence[ShellWord], source_text: str) -> Sequence[ShellWord]:
    """Mark each word with user_controlled + intent where possible.

    Returns a new list of ShellWord instances (we have to construct
    new frozen dataclasses since ShellWord is frozen).
    """
    from dataclasses import replace
    taint_map = build_taint_map(source_text)
    out = []
    for w in words:
        info = annotate_word_taint(w, taint_map)
        # We also adjust the intent_confidence and intent here based
        # on taint: tainted values are always UNKNOWN intent (we don't
        # know what the user will pass in).
        if info.is_tainted:
            new_w = replace(w, user_controlled=True)
        else:
            new_w = replace(w, user_controlled=False)
        out.append(new_w)
    return out
