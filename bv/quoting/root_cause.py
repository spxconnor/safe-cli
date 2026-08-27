"""bv/quoting/root_cause.py — root-cause diagnostic JSON output.

Spec section 19 mandates a structured diagnostic model:

    {
      "type": "quoting",
      "root_cause": "unquoted parameter expansion",
      "location": {"file": "script.sh", "line": 42, "column": 17},
      "risk": "word splitting/pathname expansion",
      "repair": {"strategy": "quote_parameter_expansion", "confidence": "HIGH"},
      "confidence": "HIGH"
    }

For complex cases we may have:

    {
      "type": "nested_quoting",
      "root_cause": "remote shell string contains locally expanded variable",
      "confidence": "LOW",
      "automatic_repair": "NOT_ATTEMPTED"
    }

This module takes the existing FindingView records from renderer.py
and reshapes them into the spec's root-cause JSON contract. It also
takes NestedBoundary records and emits their own diagnostic entries.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .nested_lang import NestedBoundary, find_max_risk, is_quoting_hell
from .renderer import FindingView


# ---------------------------------------------------------------------------
# RootCause record
# ---------------------------------------------------------------------------


# Severity / risk vocabulary used in the JSON output.
SEVERITIES = {"info", "warning", "error", "critical"}


@dataclass(frozen=True)
class RootCauseDiagnostic:
    """One root-cause diagnostic.

    Serializes to the JSON shape from spec section 19.
    """
    type: str                       # 'quoting' | 'nested_quoting' | 'syntax' | 'parser_disagreement' | ...
    root_cause: str
    location: Dict[str, Any]        # {file, line, column}
    risk: str                       # free text describing the risk
    repair: Optional[Dict[str, Any]]  # {strategy, confidence} or None
    confidence: str                 # 'HIGH' | 'MEDIUM' | 'LOW'
    automatic_repair: str = "ATTEMPTED"  # 'ATTEMPTED' | 'NOT_ATTEMPTED' | 'REFUSED'
    severity: str = "warning"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "type": self.type,
            "root_cause": self.root_cause,
            "location": self.location,
            "risk": self.risk,
            "repair": self.repair,
            "confidence": self.confidence,
            "automatic_repair": self.automatic_repair,
            "severity": self.severity,
        }
        # Surface the rule_id at the top level for AI agents (and our
        # text renderer) without requiring them to dig into details.
        if "rule_id" in self.details:
            out["rule_id"] = self.details["rule_id"]
        if self.details:
            out["details"] = self.details
        return out


# ---------------------------------------------------------------------------
# Root-cause classifier
# ---------------------------------------------------------------------------


# Map our internal rule IDs to (type, root_cause string).
_RULE_TYPE_MAP = {
    "BV-QUOTE-001": ("quoting", "unquoted scalar parameter expansion"),
    "BV-QUOTE-002": ("quoting", "unquoted command substitution"),
    "BV-QUOTE-003": ("quoting", "unquoted arithmetic expansion"),
    "BV-QUOTE-004": ("quoting", "unquoted expansion may undergo pathname expansion"),
    "BV-QUOTE-005": ("quoting", "unquoted expansion may disappear when empty"),
    "BV-QUOTE-006": ("dynamic_eval", "dynamic shell evaluation sink (eval / exec / source)"),
    "BV-QUOTE-007": ("quoting", "possible intentional list expansion"),
    "BV-QUOTE-008": ("array_semantics", "array expansion requires semantic review"),
    "BV-QUOTE-009": ("array_semantics", "$@ / $* semantic ambiguity"),
    "BV-QUOTE-010": ("quoting", "quote removal may change argument boundaries"),
    "BV-QUOTE-011": ("quoting", "mixed quoted and unquoted expansion"),
    "BV-QUOTE-012": ("quoting", "unsafe nested expansion"),
    "BV-QUOTE-013": ("word_splitting", "potentially unsafe word splitting"),
    "BV-QUOTE-014": ("pathname_expansion", "potentially unsafe pathname expansion"),
    "BV-QUOTE-015": ("ambiguous_intent", "ambiguous quoting intent"),
    "BV-QUOTE-016": ("semantic_change", "repair would change argument cardinality"),
    "BV-QUOTE-017": ("semantic_change", "repair would change empty-variable behavior"),
    "BV-QUOTE-018": ("semantic_change", "repair changes shell argument semantics"),
}


_RISK_TEXT_MAP = {
    "BV-QUOTE-001": "word splitting / pathname expansion",
    "BV-QUOTE-002": "word splitting / lost whitespace",
    "BV-QUOTE-004": "pathname expansion (globbing) on the unquoted value",
    "BV-QUOTE-005": "empty argument disappearance",
    "BV-QUOTE-006": "dynamic shell execution; quoting alone is not a defensive fix",
    "BV-QUOTE-007": "argument cardinality may be intentional list semantics",
    "BV-QUOTE-008": "array element boundaries",
    "BV-QUOTE-009": "$@ vs $* / ${arr[@]} vs ${arr[*]} semantics",
}


def _confidence_label(value: float) -> str:
    if value >= 0.85:
        return "HIGH"
    if value >= 0.5:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Top-level: render findings as root-cause diagnostics
# ---------------------------------------------------------------------------


def to_root_cause_diagnostics(
    findings: Sequence[FindingView],
    *,
    file_path: Optional[str] = None,
) -> List[RootCauseDiagnostic]:
    out: List[RootCauseDiagnostic] = []
    for f in findings:
        type_, root_cause_text = _RULE_TYPE_MAP.get(
            f.rule_id, ("quoting", f.title)
        )
        risk_text = _RISK_TEXT_MAP.get(f.rule_id, "argument-cardinality / token-boundary effects")
        conf_label = _confidence_label(f.risk.confidence)

        repair: Optional[Dict[str, Any]] = None
        automatic = "ATTEMPTED"
        if f.decision.candidate_accepted:
            repair = {
                "strategy": "wrap_in_double_quotes",
                "confidence": conf_label,
                "span": [f.candidate.start_byte, f.candidate.end_byte],
                "replacement": f.candidate.replacement,
                "rationale": f.candidate.rationale,
            }
            automatic = "ATTEMPTED"
        else:
            automatic = "NOT_ATTEMPTED"
            repair = None

        if f.risk.severity == "error":
            sev = "error"
        elif f.risk.severity == "warning":
            sev = "warning"
        else:
            sev = "info"

        out.append(
            RootCauseDiagnostic(
                type=type_,
                root_cause=root_cause_text,
                location={
                    "file": file_path or "<stdin>",
                    "line": f.location[0],
                    "column": f.location[1],
                },
                risk=risk_text,
                repair=repair,
                confidence=conf_label,
                automatic_repair=automatic,
                severity=sev,
                details={
                    "rule_id": f.rule_id,
                    "raw": f.raw_text,
                    "semantic_risk": f.risk.semantic_risk,
                    "candidate_confidence": f.risk.confidence,
                    "rejection_reason": f.decision.reason,
                },
            )
        )
    return out


def nested_boundary_to_diagnostic(
    boundary: NestedBoundary,
    file_path: Optional[str] = None,
) -> RootCauseDiagnostic:
    """Convert a NestedBoundary into a root-cause diagnostic."""
    max_risk = boundary.risk
    if max_risk == "high":
        # Spec section 28: at high risk we should refuse, not blind-quote.
        conf = "LOW"
        auto = "NOT_ATTEMPTED"
    else:
        conf = "MEDIUM"
        auto = "REFUSED"  # don't auto-repair cross-language; require review
    risk_text = (
        f"cross-language quoting boundary: {boundary.outer_command} -> "
        f"{boundary.inner_language}. Quoting alone is not safe; consider "
        f"temp files, heredoc, argument arrays, or env vars."
    )
    sev = "critical" if max_risk == "high" else "warning"
    return RootCauseDiagnostic(
        type="nested_quoting",
        root_cause=(
            f"{boundary.outer_command} command embeds {boundary.inner_language} "
            "code; quoting repair needs structural awareness."
        ),
        location={
            "file": file_path or "<stdin>",
            "line": None,        # line/column require AST lookup; kept None
            "column": None,
            "span": list(boundary.span),
        },
        risk=risk_text,
        repair=None,
        confidence=conf,
        automatic_repair=auto,
        severity=sev,
        details={
            "rule_id": "BV-NESTED-001",
            "outer_command": boundary.outer_command,
            "inner_language": boundary.inner_language,
            "risk_level": max_risk,
            "advice": (
                "Restructure: use a heredoc, temp file, or argument array "
                "to eliminate the cross-language quoting nest."
            ),
        },
    )


# ---------------------------------------------------------------------------
# Aggregate render
# ---------------------------------------------------------------------------


def render_root_cause_report(
    findings: Sequence[FindingView],
    boundaries: Sequence[NestedBoundary],
    *,
    file_path: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Render the full root-cause JSON output.

    This is the canonical AI-agent contract from spec section 27.
    """
    diags_quoting = to_root_cause_diagnostics(findings, file_path=file_path)
    diags_nested = [
        nested_boundary_to_diagnostic(b, file_path=file_path)
        for b in boundaries
    ]
    all_diags = diags_quoting + diags_nested

    # Source fingerprint
    src_hash = ""
    if source is not None:
        src_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()

    return {
        "schema_version": 1,
        "type": "safe-cli.bash-verify",
        "file": file_path or "<stdin>",
        "source_sha256": src_hash,
        "status": _overall_status(findings, boundaries),
        "diagnostics": [d.to_dict() for d in all_diags],
        "summary": {
            "total": len(all_diags),
            "quoting": len(diags_quoting),
            "nested_language": len(diags_nested),
            "high_confidence": sum(1 for d in all_diags if d.confidence == "HIGH"),
            "auto_repair_attempted": sum(
                1 for d in all_diags if d.automatic_repair == "ATTEMPTED"
            ),
            "auto_repair_refused": sum(
                1 for d in all_diags if d.automatic_repair in ("REFUSED", "NOT_ATTEMPTED")
            ),
            "max_risk_level": find_max_risk(boundaries) if boundaries else "low",
            "is_quoting_hell": is_quoting_hell(boundaries),
        },
    }


def _overall_status(findings: Sequence[FindingView], boundaries: Sequence[NestedBoundary]) -> str:
    if is_quoting_hell(boundaries):
        return "QUOTING_HELL_REFUSED"
    refused = [f for f in findings if not f.decision.candidate_accepted]
    auto_eligible = [f for f in findings if f.risk.auto_repair_eligible]
    if auto_eligible and not refused:
        return "REPAIRABLE"
    if not findings and not boundaries:
        return "PASS"
    if not auto_eligible:
        return "REVIEW_REQUIRED"
    return "REPAIRABLE"
