"""JSON report formatter."""
from __future__ import annotations

import json
from typing import Any

from ..diagnostic import Severity


def to_json(report) -> str:
    """Render a VerificationReport as JSON.

    Args:
        report: a `Orchestrator.VerificationReport` instance.
    """
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def to_summary_dict(report) -> dict[str, Any]:
    """Compact summary for CI dashboards."""
    return {
        "status": report.status,
        "duration_ms": report.duration_ms,
        "layer_count": len(report.layers),
        "layer_pass": sum(1 for r in report.layers.values() if r.status == "pass"),
        "layer_warn": sum(1 for r in report.layers.values() if r.status == "warn"),
        "layer_fail": sum(1 for r in report.layers.values() if r.status == "fail"),
        "diagnostic_count": len(report.all_diagnostics()),
        "blocking_count": len([d for d in report.all_diagnostics() if d.severity == Severity.ERROR]),
    }
