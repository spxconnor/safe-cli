"""bv/quoting — Conservative Bash Quoting Intelligence & Self-Healing Engine.

This package implements a careful, conservative analyzer that finds
risky unquoted expansions and proposes minimal source-span edits to
fix them, while never blindly quoting array/list semantics.

Public API:

    analyze(source: str) -> list[ShellWord]
        Tokenize Bash source and return ShellWord records.

    analyze_with_intent(source: str) -> list[ShellWord]
        analyze() + semantics-based intent + dataflow taint.

    find_findings(source: str) -> list[FindingView]
        Run the full pipeline (analyzer + dataflow + rules + risk +
        candidates + planner) and return ready-to-render findings.

    apply_repair(source: str, finding: FindingView,
                 *, target_path=None, backup_path=None) -> RepairOutcome
        Apply (or refuse) a single finding's candidate.

    render_text(findings) -> str
    render_json(findings) -> dict

DESIGN PRINCIPLES (re-stated for reviewers):
    - Conservative: when in doubt, refuse auto-repair.
    - Source-span based: no str.replace, no global regex rewrites.
    - Heredoc-aware: heredoc bodies are protected lexical regions.
    - Sandbox-validated: behavioral validation goes through the
      existing ExecutionBroker; we never bypass the host boundary.
    - Idempotent: fix(fix(x)) == fix(x) for accepted repairs.
    - Non-destructive: original files are only modified via explicit
      atomic-write + backup; refused repairs never touch disk.
"""
from __future__ import annotations

from dataclasses import replace
from typing import List, Optional, Sequence, Tuple

from .analyzer import analyze as _analyze, filter_words_with_unsafe_expansions
from .candidates import Candidate, generate_candidates
from .dataflow import apply_dataflow
from .model import (
    ContextKind,
    Expansion,
    Intent,
    QuoteType,
    SemanticFlags,
    ShellWord,
)
from .planner import OscillationGuard, PlanDecision, RepairBudget, plan
from .renderer import FindingView, render_findings_json, render_findings_text
from .repairs import (
    QuoteRepairProposal,
    RepairCertificate,
    RepairOutcome,
    apply_to_text,
    run_repair,
)
from .risk import RiskAssessment, assess
from .rules import RULES, RuleDef, rules_for
from .semantics import (
    ExpansionKind,
    classify_expansion,
    classify_intent,
    compute_semantic_flags,
)
from .validator import ValidationResult, validate_static


__all__ = [
    "analyze",
    "analyze_with_intent",
    "find_findings",
    "apply_repair",
    "render_text",
    "render_json",
    "ContextKind",
    "Expansion",
    "ExpansionKind",
    "Intent",
    "OscillationGuard",
    "PlanDecision",
    "QuoteType",
    "QuoteRepairProposal",
    "RepairBudget",
    "RepairCertificate",
    "RepairOutcome",
    "RiskAssessment",
    "RuleDef",
    "RULES",
    "SemanticFlags",
    "ShellWord",
    "ValidationResult",
    "Candidate",
]


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------


def analyze(source: str) -> List[ShellWord]:
    """Tokenize Bash source and return ShellWord records (no dataflow)."""
    return _analyze(source)


def analyze_with_intent(source: str) -> List[ShellWord]:
    """analyze() + intent classification + dataflow taint tracking."""
    words = _analyze(source)
    # Apply semantic flags
    words = [replace(w, semantic=compute_semantic_flags(w)) for w in words]
    # Apply intent classification
    new_words: List[ShellWord] = []
    for w in words:
        intent, confidence, evidence = classify_intent(w)
        new_words.append(
            replace(w, intent=intent, intent_confidence=confidence, intent_evidence=evidence)
        )
    # Apply dataflow taint
    new_words = list(apply_dataflow(new_words, source))
    return new_words


def _build_finding(
    word: ShellWord, source: str
) -> Tuple[FindingView, RuleDef, Candidate, RiskAssessment, PlanDecision]:
    rules = rules_for(word)
    if not rules:
        # Should never happen because we filter upstream, but defensive.
        raise ValueError("no rules matched")
    risk = assess(word, rules)
    # Pick the first rule whose default_repair_kind yields a non-None
    # candidate, else the first rule.
    candidates = generate_candidates(word, rules)
    chosen_candidate: Optional[Candidate] = None
    for c in candidates:
        if c.replacement != word.raw_text or c.requires_explicit_authorization:
            chosen_candidate = c
            break
    if chosen_candidate is None:
        chosen_candidate = candidates[0]
    decision = plan(word, chosen_candidate, risk, rules, source)
    semantic_dict = {
        "word_splitting": word.semantic.word_splitting_possible,
        "pathname_expansion": word.semantic.pathname_expansion_possible,
        "empty_disappear": word.semantic.empty_value_can_disappear,
        "parameter_expansion": word.semantic.parameter_expansion,
        "command_substitution": word.semantic.command_substitution,
    }
    explanation: Tuple[str, ...] = ()
    if word.intent in (Intent.LIST, Intent.ARRAY):
        explanation = (
            "Possible intent: list / array semantics.",
            "Automatic quoting would change argument cardinality.",
            "Use \"${arr[@]}\" if list semantics are intended.",
        )
    elif word.context_kind == ContextKind.ASSIGNMENT:
        explanation = (
            "Word is on RHS of an assignment; word splitting does not apply.",
            "Quoting still recommended for clarity and pathname safety.",
        )
    finding = FindingView(
        rule_id=chosen_candidate.rule_id,
        title=rules[0].title,
        location=(word.start_line, word.start_column),
        raw_text=word.raw_text,
        semantic=semantic_dict,
        risk=risk,
        candidate=chosen_candidate,
        decision=decision,
        explanation=explanation,
    )
    return finding, rules[0], chosen_candidate, risk, decision


def find_findings(source: str) -> List[FindingView]:
    """Run the full pipeline and return ready-to-render findings.

    Skips words that don't have unsafe expansions. Returns an empty
    list if the source has no quoting issues.
    """
    words = analyze_with_intent(source)
    interesting = filter_words_with_unsafe_expansions(words)
    # Also surface intent-only words for ambiguous cases (list/scalar
    # ambiguity). We do this with a separate pass.
    from .model import Intent
    ambiguous = [
        w for w in words
        if w.intent in (Intent.LIST, Intent.ARRAY)
        and not w.is_in_heredoc_body
        and w.quote_type not in (QuoteType.SINGLE, QuoteType.DOUBLE)
        and w not in interesting
    ]
    findings: List[FindingView] = []
    for w in interesting:
        try:
            f, *_ = _build_finding(w, source)
            findings.append(f)
        except Exception:
            continue
    for w in ambiguous:
        try:
            f, *_ = _build_finding(w, source)
            findings.append(f)
        except Exception:
            continue
    return findings


def apply_repair(
    source: str,
    finding: FindingView,
    *,
    target_path: Optional[str] = None,
    backup_path: Optional[str] = None,
    require_validation: bool = True,
) -> RepairOutcome:
    """Apply (or refuse) a single finding's candidate."""
    # Reconstruct a minimal ShellWord-like object for run_repair.
    # We need start/end; we pull them from the candidate span.
    from .model import ContextKind, QuoteType, SemanticFlags, ShellWord
    sw = ShellWord(
        start_byte=finding.candidate.start_byte,
        end_byte=finding.candidate.end_byte,
        start_line=finding.location[0],
        start_column=finding.location[1],
        raw_text=finding.raw_text,
        quote_type=QuoteType.NONE,
        semantic=SemanticFlags(
            word_splitting_possible=finding.semantic.get("word_splitting", False),
            pathname_expansion_possible=finding.semantic.get("pathname_expansion", False),
            empty_value_can_disappear=finding.semantic.get("empty_disappear", False),
            parameter_expansion=finding.semantic.get("parameter_expansion", False),
            command_substitution=finding.semantic.get("command_substitution", False),
        ),
        context_kind=ContextKind.OTHER,
    )
    return run_repair(
        source,
        sw,
        finding.candidate,
        finding.decision,
        target_path=target_path,
        backup_path=backup_path,
        require_validation=require_validation,
    )


def render_text(findings: Sequence[FindingView]) -> str:
    return render_findings_text(findings)


def render_json(findings: Sequence[FindingView]) -> dict:
    return render_findings_json(findings)
