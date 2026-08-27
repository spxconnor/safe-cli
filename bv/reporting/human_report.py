"""Human-readable report formatter."""
from __future__ import annotations

from typing import Any


def to_human(report) -> str:
    """Render a VerificationReport as plain text for terminals."""
    out: list[str] = []
    out.append("=" * 64)
    out.append("BASH VERIFICATION REPORT")
    out.append("=" * 64)
    out.append(f"Script: {report.script_path}")
    out.append(f"Status: {report.status}")
    out.append(f"FP:     {report.script_fingerprint[:16]}")
    out.append(f"Time:   {report.duration_ms} ms")
    out.append("")
    out.append("Layers:")
    for name, lr in report.layers.items():
        n = len(lr.diagnostics)
        out.append(f"  - {name:<14} {lr.status:<5} {n:>4} diag  {lr.duration_ms} ms")
    out.append("")
    if report.repair:
        rr = report.repair
        out.append("Self-healing:")
        out.append(f"  attempts: {rr.total_attempts}")
        out.append(f"  healed:   {rr.self_healed}")
        out.append(f"  aborted:  {rr.aborted_reason or '(no)'}")
        for a in rr.attempts:
            out.append(f"   #{a.attempt_number} strategy={a.strategy_used} "
                       f"diag {len(a.diagnostics_before)} -> {len(a.diagnostics_after)}")
    out.append("")
    blocking = report.above_threshold(__import__("bv.diagnostic", fromlist=["Severity"]).Severity("warning"))
    if blocking:
        out.append(f"Blocking diagnostics ({len(blocking)}):")
        for d in blocking[:50]:
            out.append(f"  * {d.short()}")
        if len(blocking) > 50:
            out.append(f"  ... and {len(blocking) - 50} more")
    else:
        out.append("No blocking diagnostics.")
    return "\n".join(out)
