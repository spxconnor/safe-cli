"""bv/quoting/renderer.py - human + JSON rendering for quoting findings.

Spec sections 43, 44, 77, 78, 79 specify what the user / agent sees.

We expose two renderers:
  - render_finding_text(finding) -> str        (the human-readable form)
  - render_finding_json(finding) -> dict      (machine-readable)

The `finding` type is opaque to callers; it is whatever the
analyzer+rules pipeline produces. The renderer must NEVER mutate the
finding; it must produce a deterministic, stable string.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .candidates import Candidate
from .model import ShellWord
from .planner import PlanDecision
from .risk import RiskAssessment


@dataclass(frozen=True)
class FindingView:
    """A single finding assembled from analyzer + rules + risk + planner."""
    rule_id: str
    title: str
    location: Tuple[int, int]                # (line, column)
    raw_text: str
    semantic: Dict[str, bool]
    risk: RiskAssessment
    candidate: Candidate
    decision: PlanDecision
    explanation: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def render_finding_json(f: FindingView) -> Dict[str, Any]:
    return {
        "rule": f.rule_id,
        "title": f.title,
        "location": {"line": f.location[0], "column": f.location[1]},
        "raw": f.raw_text,
        "semantic": f.semantic,
        "risk": {
            "severity": f.risk.severity,
            "confidence": f.risk.confidence,
            "semantic_risk": f.risk.semantic_risk,
            "auto_repair_eligible": f.risk.auto_repair_eligible,
            "reason": f.risk.reason,
        },
        "candidate": {
            "replacement": f.candidate.replacement,
            "span": [f.candidate.start_byte, f.candidate.end_byte],
            "semantic_risk": f.candidate.semantic_risk,
            "cardinality_delta": f.candidate.cardinality_delta,
            "rationale": f.candidate.rationale,
        },
        "decision": {
            "accepted": f.decision.candidate_accepted,
            "reason": f.decision.reason,
        },
        "explanation": list(f.explanation),
    }


def render_findings_json(findings: Sequence[FindingView]) -> Dict[str, Any]:
    return {
        "findings": [render_finding_json(f) for f in findings],
        "summary": {
            "total": len(findings),
            "auto_repair_eligible": sum(1 for f in findings if f.risk.auto_repair_eligible),
            "refused": sum(1 for f in findings if not f.decision.candidate_accepted),
        },
    }


# ---------------------------------------------------------------------------
# Text output
# ---------------------------------------------------------------------------


def _severity_label(s: str) -> str:
    s = (s or "").upper()
    if s == "ERROR":
        return "ERROR"
    if s == "WARNING":
        return "WARNING"
    return "INFO"


def _yesno(b: bool) -> str:
    return "yes" if b else "no"


def render_finding_text(f: FindingView) -> str:
    lines: List[str] = []
    lines.append(f.rule_id)
    lines.append("")
    lines.append(f.title)
    lines.append("")
    lines.append(f"Line {f.location[0]}, column {f.location[1]}")
    lines.append("")
    lines.append("Expansion:")
    lines.append(f"    {f.raw_text}")
    lines.append("")
    sem = f.semantic
    effects: List[str] = []
    if sem.get("word_splitting"):
        effects.append("word splitting")
    if sem.get("pathname_expansion"):
        effects.append("pathname expansion")
    if sem.get("empty_disappear"):
        effects.append("empty argument disappearance")
    if not effects:
        effects.append("(no expansion-driven side effect detected)")
    lines.append("Potential effects:")
    for e in effects:
        lines.append(f"    - {e}")
    lines.append("")
    lines.append("Risk assessment:")
    lines.append(f"    severity: {_severity_label(f.risk.severity)}")
    lines.append(f"    confidence: {f.risk.confidence:.2f}")
    lines.append(f"    semantic risk: {f.risk.semantic_risk}")
    lines.append(f"    auto-repair eligible: {_yesno(f.risk.auto_repair_eligible)}")
    lines.append("")
    if f.candidate.replacement != f.raw_text:
        lines.append("Suggested repair:")
        lines.append(f"    {f.raw_text} -> {f.candidate.replacement}")
    else:
        lines.append("Suggested repair:")
        lines.append("    (none — see explanation)")
    lines.append("")
    lines.append(f"Decision: {'ACCEPTED' if f.decision.candidate_accepted else 'REFUSED'}")
    lines.append(f"    reason: {f.decision.reason}")
    lines.append("")
    if f.explanation:
        lines.append("Explanation:")
        for line in f.explanation:
            lines.append(f"    {line}")
    return "\n".join(lines)


def render_findings_text(findings: Sequence[FindingView]) -> str:
    if not findings:
        return "No quoting findings."
    out: List[str] = []
    out.append("Quoting findings")
    out.append("=" * 60)
    out.append("")
    out.append(f"Total findings: {len(findings)}")
    out.append(
        f"Auto-repair eligible: {sum(1 for f in findings if f.risk.auto_repair_eligible)}"
    )
    out.append(f"Refused: {sum(1 for f in findings if not f.decision.candidate_accepted)}")
    out.append("")
    for i, f in enumerate(findings, start=1):
        out.append("-" * 60)
        out.append(f"Finding #{i}")
        out.append(render_finding_text(f))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Concise AI-agent output (spec section 79)
# ---------------------------------------------------------------------------


def render_agent_decision(f: FindingView) -> Dict[str, Any]:
    if f.decision.candidate_accepted:
        return {
            "status": "auto_repair_eligible",
            "rule": f.rule_id,
            "problem": f.title,
            "safe_fix": f.candidate.replacement,
            "reason": f.decision.reason,
            "suggestion": f.candidate.replacement,
        }
    return {
        "status": "needs_review",
        "rule": f.rule_id,
        "problem": f.title,
        "safe_fix": None,
        "reason": f.decision.reason,
        "suggestion": (
            "Use an array and \"${arr[@]}\" when list semantics are intended"
            if "list" in (f.title or "").lower() or "array" in (f.title or "").lower()
            else "Manual review required"
        ),
    }
