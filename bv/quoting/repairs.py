"""bv/quoting/repairs.py - apply source-span edits to create new Artifacts.

Spec section 40 requires the transaction model:

    original Artifact
    candidate Artifact
    verification result
    decision
    commit result

Spec section 41 requires an atomic commit: write to a temp file in
the same filesystem, flush, fsync, rename.

We INTEGRATE with the existing safe-cli abstractions:
  - `bv.artifact.Artifact` for content-addressed identity
  - `bv.script.Script` for source-file backup
  - `bv.repair.engine.RepairEngine` is NOT bypassed — we expose a
    `QuoteRepairProposal` that the existing repair framework can pick
    up if the user opts in.

We do NOT use the existing repair engine here for the *automatic*
flow: that engine is a try-then-test loop that runs the verification
pipeline. Our quoting flow is more constrained (we only know how to
do specific edits), and it is intentionally simpler than the general
repair loop. We share the same Artifact identity model so downstream
verification can be performed uniformly.

For source-span application we never use str.replace; we always
substitute on byte offsets.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .candidates import Candidate
from .model import ShellWord
from .planner import OscillationGuard, PlanDecision, RepairBudget
from .validator import ValidationResult, apply_candidate, validate_static


@dataclass(frozen=True)
class RepairCertificate:
    """Evidence-style record for an accepted repair.

    Per spec section 66 this is NOT a mathematical proof. It is a
    documented certificate of the evidence we gathered at repair time.
    """
    rule_id: str
    before_sha256: str
    after_sha256: str
    confidence: float
    semantic_risk: str
    changed_spans: Tuple[Tuple[int, int, str, str], ...] = ()  # (start, end, before, after)
    syntax_verified: bool = False
    parser_round_trip_ok: bool = False
    semantic_checks_passed: bool = False
    behavior_verified: bool = False
    security_regression: bool = False
    notes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RepairOutcome:
    """The full result of attempting a quoting repair on one candidate.

    Spec section 2 of the hardening pass: explicit semantics for each
    boolean. A repair goes through several distinct stages and the
    outcome records each one explicitly. The contract is:

      candidate_created : True iff we produced a candidate replacement
                         string and computed its SHA256.
      validated         : True iff validation (when required) succeeded
                         for the candidate. False means we refused the
                         candidate outright.
      persisted         : True iff we successfully wrote the candidate
                         bytes to `target_path` AND the on-disk hash
                         matched the candidate hash. The atomic-write
                         step is the only step that sets this True.
      applied           : True iff the persisted bytes were actually
                         accepted as the new file contents. Currently
                         `applied == persisted` because the only way to
                         become persisted is to write successfully.

    `applied` and `persisted` are kept distinct because future paths
    (e.g. an interrupted write that left a partial temp file) may update
    them independently. Callers that just need to know "did anything
    happen on disk?" should check `persisted`. Callers that need to
    distinguish "I calculated a candidate" from "I wrote it" should
    check `applied`.

    Read-only callers (target_path is None) get:
      candidate_created = True
      validated         = True (or False if validation failed)
      persisted         = False
      applied           = False
    """
    candidate: Candidate
    decision: PlanDecision
    validation: ValidationResult
    # Spec section 2: explicit booleans. Each is independent.
    candidate_created: bool = False
    validated: bool = False
    persisted: bool = False
    applied: bool = False
    new_sha256: str = ""           # SHA256 of the candidate bytes (when created)
    certificate: Optional[RepairCertificate] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Source-span application
# ---------------------------------------------------------------------------


def apply_to_text(source: str, candidate: Candidate) -> str:
    """Apply a candidate to source text and return the new text.

    Pure function. No disk I/O.
    """
    return apply_candidate(source, candidate)


# ---------------------------------------------------------------------------
# Disk write with backup + atomic rename
# ---------------------------------------------------------------------------


def _atomic_write_text(path: str, content: str) -> None:
    """Write `content` to `path` atomically.

    Steps:
      1. Compute target directory and ensure it exists.
      2. Create a NamedTemporaryFile in the SAME directory.
      3. Write + flush + fsync.
      4. os.replace() to the final path.

    This guarantees that either the old file is intact or the new file
    is fully written — there is no partial-write state.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".safe-cli-quote-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync may fail on some filesystems; we still proceed
                pass
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup of the temp file.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Repair proposal: integration with the existing repair engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuoteRepairProposal:
    """An integration point for the existing repair framework.

    The quoting subsystem produces this when an automatic repair is
    approved. The existing repair framework (bv.repair.engine) can pick
    it up and run its standard pipeline.
    """
    rule_id: str
    before_sha256: str
    after_sha256: str
    span_start: int
    span_end: int
    replacement: str
    certificate: RepairCertificate


# ---------------------------------------------------------------------------
# Main repair driver
# ---------------------------------------------------------------------------


def run_repair(
    source: str,
    word: ShellWord,
    candidate: Candidate,
    decision: PlanDecision,
    *,
    target_path: Optional[str] = None,
    backup_path: Optional[str] = None,
    require_validation: bool = True,
) -> RepairOutcome:
    """Apply or refuse a single candidate repair.

    Contract (Spec section 2 of the hardening pass):

      READ-ONLY call (target_path is None):
        candidate_created = True iff we produced the candidate bytes
        validated         = True iff validation passed (or wasn't required)
        persisted         = False  (NEVER set without an actual disk write)
        applied           = False  (NEVER set without an actual disk write)

      PERSISTING call (target_path is given, validation passes, atomic
      write succeeds, post-write hash matches candidate hash):
        candidate_created = True
        validated         = True
        persisted         = True
        applied           = True

    Any I/O or hash-mismatch failure yields persisted=False, applied=False,
    error=<message>.

    - `source`         the original source text
    - `word`           the ShellWord the candidate refers to
    - `candidate`      the Candidate to apply
    - `decision`       the planner's verdict
    - `target_path`    if given, we write the new content to this file
                       atomically; otherwise we just return the bytes
    - `backup_path`    if given, we copy the original file here first
    - `require_validation` if True, we run the static validation chain
                            and refuse to apply if it fails

    Returns a RepairOutcome. NEVER throws for a refused repair; throws
    only on I/O errors when the caller asked us to write.
    """
    before_sha = _hash_str(source)
    span_text = source[word.start_byte:word.end_byte]

    if not decision.candidate_accepted:
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=ValidationResult(False, False, False, True, before_sha, ("refused",), ()),
            candidate_created=False,
            validated=False,
            persisted=False,
            applied=False,
            new_sha256="",
            certificate=None,
            error="planner refused candidate",
        )

    # Candidate is created.
    new_source = apply_to_text(source, candidate)
    after_sha = _hash_str(new_source)

    validation = ValidationResult(False, False, False, True, after_sha, ("skipped",), ())
    if require_validation:
        validation = validate_static(source, candidate)

    cert = RepairCertificate(
        rule_id=candidate.rule_id,
        before_sha256=before_sha,
        after_sha256=after_sha,
        confidence=decision.confidence,
        semantic_risk=decision.semantic_risk,
        changed_spans=((word.start_byte, word.end_byte, span_text, candidate.replacement),),
        syntax_verified=validation.bash_n_ok,
        parser_round_trip_ok=validation.parser_round_trip_ok,
        semantic_checks_passed=validation.passed,
        behavior_verified=False,  # only set when differential validation ran
        security_regression=False,
        notes=validation.notes,
    )

    if require_validation and not validation.passed:
        # Refuse to apply a candidate that fails static validation.
        # We produced a candidate but explicitly did NOT validate it.
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=validation,
            candidate_created=True,
            validated=False,
            persisted=False,
            applied=False,
            new_sha256=after_sha,
            certificate=cert,
            error="static validation failed",
        )

    # READ-ONLY path: candidate created, validated, never persisted.
    if target_path is None:
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=validation,
            candidate_created=True,
            validated=True,
            persisted=False,
            applied=False,
            new_sha256=after_sha,
            certificate=cert,
        )

    # PERSISTING path: backup (optional), atomic write, then verify the
    # resulting on-disk hash matches the candidate hash before claiming
    # success.
    if backup_path is not None:
        try:
            # Backup is a COPY, not a move; we never destroy the original.
            _atomic_write_text(backup_path, source)
        except Exception as e:
            return RepairOutcome(
                candidate=candidate,
                decision=decision,
                validation=validation,
                candidate_created=True,
                validated=True,
                persisted=False,
                applied=False,
                new_sha256=after_sha,
                certificate=cert,
                error=f"backup failed: {e}",
            )
    try:
        _atomic_write_text(target_path, new_source)
    except Exception as e:
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=validation,
            candidate_created=True,
            validated=True,
            persisted=False,
            applied=False,
            new_sha256=after_sha,
            certificate=cert,
            error=f"atomic write failed: {e}",
        )

    # Spec section 2F: post-write hash recheck. The atomic rename is supposed
    # to be atomic, but defense in depth: verify the file actually contains
    # the bytes we intended.
    try:
        with open(target_path, "rb") as f:
            written = f.read()
    except Exception as e:
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=validation,
            candidate_created=True,
            validated=True,
            persisted=False,
            applied=False,
            new_sha256=after_sha,
            certificate=cert,
            error=f"post-write read failed: {e}",
        )
    written_sha = hashlib.sha256(written).hexdigest()
    if written_sha != after_sha:
        return RepairOutcome(
            candidate=candidate,
            decision=decision,
            validation=validation,
            candidate_created=True,
            validated=True,
            persisted=False,
            applied=False,
            new_sha256=after_sha,
            certificate=cert,
            error=(
                f"post-write hash mismatch: expected {after_sha[:16]}... "
                f"on disk got {written_sha[:16]}..."
            ),
        )

    return RepairOutcome(
        candidate=candidate,
        decision=decision,
        validation=validation,
        candidate_created=True,
        validated=True,
        persisted=True,
        applied=True,
        new_sha256=after_sha,
        certificate=cert,
    )


# ---------------------------------------------------------------------------
# Idempotence / oscillation guard
# ---------------------------------------------------------------------------


def make_oscillation_guard() -> OscillationGuard:
    return OscillationGuard()
