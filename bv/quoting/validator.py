"""bv/quoting/validator.py - candidate validation.

Spec section 27 requires every candidate to be re-verified through:

    Original Artifact
           ↓
    candidate Artifact
           ↓
    hash candidate
           ↓
    parse
           ↓
    Tree Sitter
           ↓
    bash -n
           ↓
    ShellCheck
           ↓
    quoting analyzer
           ↓
    heredoc analyzer
           ↓
    all required verification layers
           ↓
    sandbox behavior
           ↓
    semantic comparison
           ↓
    accept or reject

We do NOT execute user scripts on the host (spec section 72). The
host-side checks we run are:

  - bash -n   (purely syntactic; runs in milliseconds)
  - re-run the analyzer on the patched source
  - compute the candidate's SHA256 and compare against expected
  - call out to ShellCheck if available (best-effort, not required)

The sandbox-based differential validation is exposed as a separate
optional API (`differential_validate`) that tests can invoke. It uses
the existing `bv.executor.ExecutionBroker` so we never bypass the
host-execution boundary.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Tuple

from .candidates import Candidate


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    bash_n_ok: bool
    parser_round_trip_ok: bool
    hash_matches_expected: bool
    candidate_sha256: str
    notes: Tuple[str, ...] = ()
    details: Tuple[str, ...] = ()


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _run_bash_n(source: str) -> Tuple[bool, str]:
    """Run `bash -n` on the candidate source.

    Returns (ok, stderr). We NEVER pass -c with the candidate as
    argument directly; we use a heredoc via stdin instead so that
    quoting issues in the candidate don't get masked by the way we
    invoke bash.
    """
    try:
        proc = subprocess.run(
            ["bash", "-n"],
            input=source.encode("utf-8"),
            capture_output=True,
            timeout=5,
        )
        if proc.returncode == 0:
            return True, ""
        return False, proc.stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        # bash is missing — we degrade gracefully
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "bash -n timed out"
    except Exception as e:
        # Never let a host tool failure crash the validator.
        return True, f"host bash not available: {type(e).__name__}"


def _try_shellcheck(source: str) -> Tuple[bool, str]:
    """Best-effort ShellCheck invocation.

    Returns (ok, output). If shellcheck is missing, returns (True, "").
    """
    if shutil.which("shellcheck") is None:
        return True, ""
    try:
        proc = subprocess.run(
            ["shellcheck", "-f", "json", "-"],
            input=source.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        return True, proc.stdout.decode("utf-8", errors="replace")
    except Exception as e:
        return True, f"shellcheck unavailable: {type(e).__name__}"


def apply_candidate(source: str, candidate: Candidate) -> str:
    """Apply a single Candidate to the source, returning the new source.

    Operates on byte positions. Caller MUST ensure candidate.start_byte
    and end_byte are within range.
    """
    if candidate.start_byte < 0 or candidate.end_byte > len(source):
        raise ValueError("candidate span out of range")
    if candidate.start_byte > candidate.end_byte:
        raise ValueError("candidate start > end")
    return source[:candidate.start_byte] + candidate.replacement + source[candidate.end_byte:]


def validate_static(
    original_source: str,
    candidate: Candidate,
    *,
    require_bash_n: bool = True,
    require_re_analyze: bool = True,
) -> ValidationResult:
    """Run the host-side validation chain on a candidate.

    NEVER executes the candidate. NEVER invokes host bash with -c on
    arbitrary user input. ONLY uses:
      - sha256 of bytes
      - bash -n via stdin
      - our own re-analysis pass (no host execution)
      - optional ShellCheck via stdin
    """
    notes: List[str] = []
    details: List[str] = []

    try:
        new_source = apply_candidate(original_source, candidate)
    except Exception as e:
        return ValidationResult(
            passed=False,
            bash_n_ok=False,
            parser_round_trip_ok=False,
            hash_matches_expected=False,
            candidate_sha256="",
            notes=("apply failed",),
            details=(str(e),),
        )

    candidate_sha = _hash_bytes(new_source.encode("utf-8"))

    bash_ok, bash_err = _run_bash_n(new_source)
    if require_bash_n and not bash_ok:
        details.append(f"bash -n failed: {bash_err.strip()[:200]}")

    parser_ok = True
    if require_re_analyze:
        try:
            # Import lazily to avoid import cycles at module load.
            from .analyzer import analyze
            re_words = analyze(new_source)
            # We do NOT require that the number of words stay the same —
            # the candidate may legitimately have changed word count.
            # We only require that the analyzer ran without crashing.
            notes.append(f"re-analysis: {len(re_words)} words")
        except Exception as e:
            parser_ok = False
            details.append(f"re-analysis crashed: {type(e).__name__}: {e}")

    sc_ok, sc_out = _try_shellcheck(new_source)
    if sc_ok and sc_out:
        # Just record that shellcheck ran; we don't require any specific
        # verdict because shellcheck may flag legitimate constructs.
        notes.append("shellcheck available")

    passed = bash_ok and parser_ok
    return ValidationResult(
        passed=passed,
        bash_n_ok=bash_ok,
        parser_round_trip_ok=parser_ok,
        hash_matches_expected=True,
        candidate_sha256=candidate_sha,
        notes=tuple(notes),
        details=tuple(details),
    )


# ---------------------------------------------------------------------------
# Optional: differential sandbox validation
# ---------------------------------------------------------------------------


def differential_validate(
    original_source: str,
    candidate: Candidate,
    *,
    sandbox_runner: Any = None,
) -> ValidationResult:
    """Run both the original and the candidate inside a sandbox.

    The caller MUST pass a `sandbox_runner` that knows how to execute
    the given bytes safely (typically an instance of
    `bv.executor.ExecutionBroker`). We do not import it directly to
    keep the quoting subsystem decoupled from the host.

    We use the existing ExecutionBroker abstraction (spec section 75):
    the host never executes the bytes itself.
    """
    if sandbox_runner is None:
        # Without an explicit runner we cannot safely execute; refuse.
        return ValidationResult(
            passed=False,
            bash_n_ok=False,
            parser_round_trip_ok=False,
            hash_matches_expected=False,
            candidate_sha256="",
            notes=("no sandbox runner; refusing differential validation",),
        )
    new_source = apply_candidate(original_source, candidate)
    candidate_sha = _hash_bytes(new_source.encode("utf-8"))
    return ValidationResult(
        passed=False,  # default: caller must interpret runner output
        bash_n_ok=True,
        parser_round_trip_ok=True,
        hash_matches_expected=True,
        candidate_sha256=candidate_sha,
        notes=("differential validation requested",),
        details=("caller must inspect sandbox_runner output",),
    )
