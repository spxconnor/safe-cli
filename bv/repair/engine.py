"""Self-healing repair engine.

Runs the verification pipeline, collects diagnostics, picks repair
strategies, applies them, then re-runs the pipeline. Loops until:
  - the pipeline passes
  - max_repair_attempts is reached
  - diagnostics stop changing (no progress)
  - a hard failure (syntax error) blocks further repairs

NEVER mutates the original script in place — all edits are made in
memory and persisted only after a successful run (unless the user has
opted into write-back via context).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..config import Config
from ..diagnostic import (
    Diagnostic,
    LayerResult,
    Severity,
    Category,
    REPAIR_PRIORITY,
)
from ..script import Script
from .strategies import STRATEGIES, find_strategy


@dataclass
class RepairAttempt:
    attempt_number: int
    diagnostics_before: list[Diagnostic]
    strategy_used: str
    changed: bool
    content_hash_before: str
    content_hash_after: str
    diagnostics_after: list[Diagnostic]
    notes: list[str] = field(default_factory=list)


@dataclass
class RepairReport:
    total_attempts: int
    self_healed: bool
    attempts: list[RepairAttempt] = field(default_factory=list)
    final_diagnostics: list[Diagnostic] = field(default_factory=list)
    aborted_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "total_attempts": self.total_attempts,
            "self_healed": self.self_healed,
            "aborted_reason": self.aborted_reason,
            "attempts": [
                {
                    "attempt_number": a.attempt_number,
                    "strategy_used": a.strategy_used,
                    "changed": a.changed,
                    "content_hash_before": a.content_hash_before,
                    "content_hash_after": a.content_hash_after,
                    "diagnostics_before": [d.to_dict() for d in a.diagnostics_before],
                    "diagnostics_after": [d.to_dict() for d in a.diagnostics_after],
                    "notes": a.notes,
                }
                for a in self.attempts
            ],
            "final_diagnostics": [d.to_dict() for d in self.final_diagnostics],
        }


class RepairEngine:
    """Orchestrate repair attempts against a Script."""

    def __init__(self, config: Config, run_pipeline_fn: Callable) -> None:
        self.config = config
        self.run_pipeline = run_pipeline_fn
        self.report = RepairReport(total_attempts=0, self_healed=False)

    def attempt_repair(
        self,
        script: Script,
        layer_results: dict[str, LayerResult],
        context=None,
    ) -> RepairReport:
        """Attempt repairs until the pipeline passes or limits are hit."""
        if not self.config.verify.self_healing:
            self.report.aborted_reason = "self_healing disabled in config"
            return self.report

        initial_diagnostics = self._flatten(layer_results)
        # If no diagnostics above threshold, nothing to repair
        threshold = Severity(self.config.verify.severity_threshold)
        blocking = [d for d in initial_diagnostics if Severity(d.severity).value >= threshold.value]
        if not blocking:
            self.report.final_diagnostics = initial_diagnostics
            self.report.self_healed = False
            self.report.aborted_reason = "no blocking diagnostics"
            return self.report

        start = time.monotonic()
        deadline = start + self.config.verify.max_total_seconds
        prev_fingerprint = script.fingerprint
        consecutive_no_change = 0

        for attempt in range(1, self.config.verify.max_repair_attempts + 1):
            if time.monotonic() > deadline:
                self.report.aborted_reason = "wall-clock deadline exceeded"
                break

            # Sort blocking diagnostics by priority
            candidates = self._prioritize(blocking)
            chosen = None
            for d in candidates:
                if not d.repairable:
                    continue
                if d.severity not in (Severity.ERROR, Severity.WARNING):
                    continue
                s = find_strategy(d)
                if s:
                    chosen = (d, s)
                    break

            if chosen is None:
                self.report.aborted_reason = "no repair strategy for remaining diagnostics"
                break

            d, s = chosen
            before_hash = script.fingerprint
            new_content = s.repair(script.content, d)
            if new_content is None or new_content == script.content:
                consecutive_no_change += 1
                if consecutive_no_change >= self.config.verify.max_identical_diagnostics:
                    self.report.aborted_reason = "identical repairs yielded no change"
                    break
                # Mark this diagnostic as non-repairable and try again
                d.repairable = False
                continue

            # Apply change in memory; persist only if pipeline passes
            script.update(new_content)
            # Re-run pipeline
            new_results = self.run_pipeline(script, context=context)
            new_diagnostics = self._flatten(new_results)
            new_blocking = [n for n in new_diagnostics if Severity(n.severity).value >= threshold.value]
            attempt_rec = RepairAttempt(
                attempt_number=attempt,
                diagnostics_before=list(blocking),
                strategy_used=s.name,
                changed=True,
                content_hash_before=before_hash,
                content_hash_after=script.fingerprint,
                diagnostics_after=list(new_blocking),
                notes=[s.description],
            )
            self.report.attempts.append(attempt_rec)
            self.report.total_attempts = attempt

            if not new_blocking:
                # All blocking diagnostics gone — persist if path-based
                if script.path:
                    script.update(script.content)
                self.report.final_diagnostics = new_diagnostics
                self.report.self_healed = True
                return self.report

            if script.fingerprint == before_hash:
                consecutive_no_change += 1
            else:
                consecutive_no_change = 0

            blocking = new_blocking

        self.report.final_diagnostics = self._flatten(layer_results) if not self.report.attempts else blocking
        return self.report

    @staticmethod
    def _flatten(layer_results: dict[str, LayerResult]) -> list[Diagnostic]:
        out = []
        for r in layer_results.values():
            out.extend(r.diagnostics)
        return out

    @staticmethod
    def _prioritize(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
        order = {c: i for i, c in enumerate(REPAIR_PRIORITY)}
        return sorted(diagnostics, key=lambda d: order.get(d.category, 999))
