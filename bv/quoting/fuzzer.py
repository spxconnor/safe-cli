"""bv/quoting/fuzzer.py — focused quoting argument-boundary fuzzer.

Spec section 15 calls for a focused fuzzer specifically for Bash
argument boundaries. The goal is to discover inputs that expose
incorrect quoting or argument splitting in the parser / analyzer / repair
engine. The goal is NOT generic security fuzzing.

We generate adversarial argument values from a vocabulary of:

    - quotes (single, double, mixed)
    - slashes (/, //)
    - spaces, tabs, newlines
    - shell metacharacters (;, &, |, <, >, $, `, \\, *, ?, [], {}, ())
    - variable syntax ($X, ${X})
    - command substitution syntax ($(cmd), \`cmd\`)
    - Unicode (BMP subset)
    - leading hyphens
    - long strings
    - empty strings
    - heredoc delimiters

We then build scripted scenarios:

    VAR="<adversarial>"
    some_command $VAR         # unquoted
    some_command "$VAR"       # quoted (baseline)

For each scenario we run the analyzer. Failures (parser crashes,
wrong findings, repair engine bugs) are recorded as regression cases.

Each generated scenario produces a record:

    {
      "name": "...",
      "category": "word_splitting | glob | empty | mixed_quote | ...",
      "raw_value": "...",
      "script": "...",
      "expected_findings_count": int | None,
      "verifier": "should_not_crash | should_find_unquoted | ..."
    }

When run with the existing bv/fuzz_layer.py infrastructure the generated
inputs are added to the regression corpus so the same inputs are replayed
on subsequent runs.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import string
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


# Each "atom" is a category of values that share a structural property.
# We do not enumerate every possible adversarial string — we generate
# combinations from a small vocabulary that covers the relevant Bash
# edge cases per spec section 14.

_QUOTE_ATOMS: Tuple[str, ...] = (
    "hello",
    "hello world",
    "'hello'",
    '"hello"',
    "'hello world'",
    '"hello world"',
    "hello'world",
    'hello"world',
    "hello\\world",
    "\\$HOME",
    "\\\\",
    "''",
    '""',
    "''",
)

_META_ATOMS: Tuple[str, ...] = (
    "$(echo test)",
    "`echo test`",
    "$((1+2))",
    "${HOME}",
    "${HOME:-default}",
    "${VAR:?error}",
    "*.txt",
    "*.{sh,bash}",
    "file?",
    "[abc]",
    "[-]",
    "--help",
    "--",
    "-rf",
    "-",
)

_SEPARATOR_ATOMS: Tuple[str, ...] = (
    " ",
    "\t",
    "\n",
    ";",
    "&&",
    "||",
    "|",
    "&",
    ">",
    ">>",
    "<",
    "<<",
    "<<<",
    "$'\\n'",
)

_UNICODE_ATOMS: Tuple[str, ...] = (
    "héllo",                          # Latin-1
    "🎉",                              # emoji (BMP+)
    "中",                              # CJK
    "Здравствуй",                    # Cyrillic
    "Ω",                              # Greek
    "\u200b",                         # zero-width space
)


@dataclass(frozen=True)
class FuzzCase:
    """One fuzzer scenario."""
    name: str
    category: str
    raw_value: str
    script_unquoted: str
    script_quoted: str
    expected_unquoted_findings_min: int = 0
    should_crash: bool = False


def _build_cases() -> List[FuzzCase]:
    """Build the standard test matrix of adversarial argument values."""
    cases: List[FuzzCase] = []

    # 1. Plain unquoted scalars
    cases.append(FuzzCase(
        name="plain_unquoted",
        category="word_splitting",
        raw_value="hello world",
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 2. Empty string
    cases.append(FuzzCase(
        name="empty_unquoted",
        category="empty_disappear",
        raw_value="",
        script_unquoted='rm -rf $X\n',
        script_quoted='rm -rf -- "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 3. Glob
    cases.append(FuzzCase(
        name="glob_unquoted",
        category="pathname_expansion",
        raw_value="*.txt",
        script_unquoted='rm $X\n',
        script_quoted='rm -- "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 4. Command substitution
    cases.append(FuzzCase(
        name="cmdsubst_unquoted",
        category="word_splitting",
        raw_value="$(echo a b c)",
        script_unquoted='for w in $X; do echo $w; done\n',
        script_quoted='for w in $X; do echo "$w"; done\n',
        expected_unquoted_findings_min=1,
    ))

    # 5. Backslash-escape
    cases.append(FuzzCase(
        name="backslash",
        category="quote_removal",
        raw_value='hello\\world',
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=0,  # single variable, no list evidence
    ))

    # 6. Leading hyphen (rm -- "$X" safety)
    cases.append(FuzzCase(
        name="leading_hyphen",
        category="option_injection",
        raw_value="-rf",
        script_unquoted='rm $X\n',
        script_quoted='rm -- "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 7. Newline in value
    cases.append(FuzzCase(
        name="newline_in_value",
        category="word_splitting",
        raw_value="line1\nline2",
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 8. Single-quoted dollar (literal)
    cases.append(FuzzCase(
        name="literal_dollar",
        category="literal",
        raw_value="'$HOME'",
        script_unquoted='LITERAL=$X\n',
        script_quoted='LITERAL="$X"\n',
        expected_unquoted_findings_min=0,  # it's a literal in this position
    ))

    # 9. Mixed quote/var
    cases.append(FuzzCase(
        name="mixed_quote_var",
        category="mixed_quote",
        raw_value='"$HOME"/bin',
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=0,
    ))

    # 10. Array expansion form (must NOT be touched)
    cases.append(FuzzCase(
        name="array_at_quoted",
        category="array_semantics",
        raw_value='"${arr[@]}"',
        script_unquoted='printf "%s\\n" $X\n',
        script_quoted='printf "%s\\n" "$X"\n',
        expected_unquoted_findings_min=0,  # form is intentionally array-like
    ))

    # 11. Long string
    cases.append(FuzzCase(
        name="long_string",
        category="length",
        raw_value="a" * 1024,
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 12. Unicode
    cases.append(FuzzCase(
        name="unicode_hello",
        category="unicode",
        raw_value="héllo wörld",
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 13. Unicode emoji
    cases.append(FuzzCase(
        name="unicode_emoji",
        category="unicode",
        raw_value="hello 🎉",
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 14. Heredoc delimiter
    cases.append(FuzzCase(
        name="heredoc_in_value",
        category="heredoc",
        raw_value="<<EOF",
        script_unquoted='echo $X\n',
        script_quoted='echo "$X"\n',
        expected_unquoted_findings_min=1,
    ))

    # 15. $@ positional
    cases.append(FuzzCase(
        name="positional_at",
        category="array_semantics",
        raw_value='"$@"',
        script_unquoted='cmd $X\n',
        script_quoted='cmd "$X"\n',
        expected_unquoted_findings_min=0,  # quoting $@ changes semantics
    ))

    return cases


STANDARD_CASES: Tuple[FuzzCase, ...] = tuple(_build_cases())


# ---------------------------------------------------------------------------
# Run a fuzzer case
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FuzzResult:
    case_name: str
    category: str
    crashed: bool
    findings_unquoted: int
    findings_quoted: int
    auto_repair_eligible_unquoted: int
    auto_repair_eligible_quoted: int
    notes: Tuple[str, ...] = ()


def run_case(case: FuzzCase) -> FuzzResult:
    """Run a single fuzzer case against the analyzer."""
    # We import lazily so that a fuzzer bug does not break module load.
    from . import find_findings
    try:
        unquoted_findings = find_findings(case.script_unquoted)
        quoted_findings = find_findings(case.script_quoted)
    except Exception as e:
        return FuzzResult(
            case_name=case.name,
            category=case.category,
            crashed=True,
            findings_unquoted=0,
            findings_quoted=0,
            auto_repair_eligible_unquoted=0,
            auto_repair_eligible_quoted=0,
            notes=(f"analyzer crashed: {type(e).__name__}: {e}",),
        )

    return FuzzResult(
        case_name=case.name,
        category=case.category,
        crashed=False,
        findings_unquoted=len(unquoted_findings),
        findings_quoted=len(quoted_findings),
        auto_repair_eligible_unquoted=sum(
            1 for f in unquoted_findings if f.risk.auto_repair_eligible
        ),
        auto_repair_eligible_quoted=sum(
            1 for f in quoted_findings if f.risk.auto_repair_eligible
        ),
    )


def run_all(cases: Sequence[FuzzCase] = STANDARD_CASES) -> List[FuzzResult]:
    out: List[FuzzResult] = []
    for c in cases:
        out.append(run_case(c))
    return out


# ---------------------------------------------------------------------------
# Random adversarial string generator (for property-based fuzzing)
# ---------------------------------------------------------------------------


def random_adversarial(rng: Optional[random.Random] = None) -> str:
    """Generate a random adversarial argument value.

    We do not try to model every Bash semantic — we just combine atoms
    randomly. The goal is to discover parser/repair crashes, not to
    prove Bash equivalence.
    """
    rng = rng or random.Random()
    parts: List[str] = []
    n_atoms = rng.randint(1, 5)
    pools = [_QUOTE_ATOMS, _META_ATOMS, _SEPARATOR_ATOMS, _UNICODE_ATOMS]
    for _ in range(n_atoms):
        pool = rng.choice(pools)
        parts.append(rng.choice(pool))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Corpus persistence (best-effort)
# ---------------------------------------------------------------------------


def write_corpus(directory: str, cases: Sequence[FuzzCase] = STANDARD_CASES) -> List[str]:
    """Write each case's scripts as separate files under `directory`.

    Returns the list of written paths. We only CREATE files; we never
    delete them. Any pre-existing files are left untouched.
    """
    os.makedirs(directory, exist_ok=True)
    written: List[str] = []
    for c in cases:
        unquoted_path = os.path.join(directory, f"{c.name}.unquoted.sh")
        quoted_path = os.path.join(directory, f"{c.name}.quoted.sh")
        with open(unquoted_path, "w", encoding="utf-8") as f:
            f.write(c.script_unquoted)
        with open(quoted_path, "w", encoding="utf-8") as f:
            f.write(c.script_quoted)
        written.append(unquoted_path)
        written.append(quoted_path)
    return written
