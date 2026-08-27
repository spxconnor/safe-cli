"""Top-level orchestrator.

Composes the verification layers in order:
    tree_sitter -> bash_n -> shellcheck -> shfmt -> lsp -> bats -> sandbox
    -> adversarial -> fuzz -> side_effects

Wraps the result in a VerificationReport and invokes the repair engine
if any layer fails.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Config
from .diagnostic import Diagnostic, LayerResult, Severity, Category
from .script import Script
from .security.redaction import redact_secrets
from .cache.verify_cache import cache_get, cache_put
from .repair.engine import RepairEngine, RepairReport
from .layers.tree_sitter_layer import TreeSitterLayer
from .layers.bash_n_layer import BashNLayer
from .layers.shellcheck_layer import ShellCheckLayer
from .layers.shfmt_layer import ShfmtLayer
from .layers.lsp_layer import LSPLayer
from .layers.bats_layer import BatsLayer
from .layers.sandbox_layer import SandboxLayer
from .layers.adversarial_layer import AdversarialLayer
from .layers.fuzz_layer import FuzzLayer
from .layers.side_effects_layer import SideEffectsLayer
from .layers.base import LayerContext


LAYER_ORDER = [
    "tree_sitter",
    "bash_n",
    "shellcheck",
    "shfmt",
    "lsp",
    "bats",
    "sandbox",
    "adversarial",
    "fuzz",
    "side_effects",
]


@dataclass
class VerificationReport:
    script_path: str
    script_fingerprint: str
    status: str                                       # "verified" | "failed" | "error"
    duration_ms: int
    layers: dict[str, LayerResult] = field(default_factory=dict)
    repair: Optional[RepairReport] = None
    tools: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def all_diagnostics(self) -> list[Diagnostic]:
        out = []
        for r in self.layers.values():
            out.extend(r.diagnostics)
        return out

    def above_threshold(self, threshold: Severity) -> list[Diagnostic]:
        order = {Severity.STYLE: 0, Severity.INFO: 1, Severity.WARNING: 2, Severity.ERROR: 3}
        return [d for d in self.all_diagnostics() if order[d.severity] >= order[threshold]]

    def to_dict(self) -> dict:
        return {
            "script_path": self.script_path,
            "script_fingerprint": self.script_fingerprint,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "layers": {k: v.to_dict() for k, v in self.layers.items()},
            "repair": self.repair.to_dict() if self.repair else None,
            "tools": self.tools,
            "notes": self.notes,
            "diagnostics": [d.to_dict() for d in self.all_diagnostics()],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class Orchestrator:
    """Coordinates the verification pipeline."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.layers = {
            "tree_sitter": TreeSitterLayer(config),
            "bash_n": BashNLayer(config),
            "shellcheck": ShellCheckLayer(config),
            "shfmt": ShfmtLayer(config),
            "lsp": LSPLayer(config),
            "bats": BatsLayer(config),
            "sandbox": SandboxLayer(config),
            "adversarial": AdversarialLayer(config),
            "fuzz": FuzzLayer(config),
            "side_effects": SideEffectsLayer(config),
        }

    def run(
        self,
        script: Script,
        *,
        layers: list[str] | None = None,
        context: LayerContext | None = None,
        repair: bool = True,
    ) -> VerificationReport:
        """Run the selected layers (default: all) and optionally repair."""
        layers = layers or LAYER_ORDER
        context = context or LayerContext()
        report = VerificationReport(
            script_path=script.path.as_posix() if script.path else "<stdin>",
            script_fingerprint=script.fingerprint,
            status="in_progress",
            duration_ms=0,
            tools=self._collect_tool_versions(),
        )

        start = time.monotonic()
        layer_results: dict[str, LayerResult] = {}
        for name in layers:
            layer = self.layers.get(name)
            if layer is None:
                continue
            cached = cache_get(script.content, self.config, name)
            if cached is not None:
                cached.notes = (cached.notes or []) + ["(cache hit)"]
                layer_results[name] = cached
                continue
            try:
                result = layer.run(script, context=context)
            except Exception as e:  # noqa: BLE001 — convert to diagnostic
                result = LayerResult(layer=name, status="error")
                result.add(Diagnostic(
                    tool=name,
                    category=Category.UNKNOWN,
                    severity=Severity.ERROR,
                    message=f"Layer raised exception: {e!r}",
                    layer=name,
                    repairable=False,
                ))
            cache_put(result, script.content, self.config)
            layer_results[name] = result

            # Stop early on hard syntax failure so we don't waste time.
            if name in ("tree_sitter", "bash_n"):
                if result.status == "fail":
                    report.notes.append(
                        f"Early exit after {name}: hard syntax failure"
                    )
                    break

        report.layers = layer_results
        report.duration_ms = int((time.monotonic() - start) * 1000)

        # Repair loop
        if repair and self.config.verify.self_healing:
            engine = RepairEngine(self.config, self._replay_pipeline)
            context.attempt = 0
            repair_report = engine.attempt_repair(script, layer_results, context=context)
            report.repair = repair_report
            # If self-healing produced a passing pipeline, re-run to capture
            # the final layer states.
            if repair_report.self_healed:
                layer_results = self._replay_pipeline(script, context=context)
                report.layers = layer_results

        report.status = self._overall_status(layer_results, report)
        # Redact secrets in any captured stdout/stderr metadata before returning
        self._redact_metadata(report)
        return report

    def _replay_pipeline(
        self,
        script: Script,
        *,
        context: LayerContext | None = None,
    ) -> dict[str, LayerResult]:
        """Re-run layers after a repair. Bypasses cache."""
        context = context or LayerContext()
        out = {}
        for name in LAYER_ORDER:
            layer = self.layers[name]
            try:
                out[name] = layer.run(script, context=context)
            except Exception as e:  # noqa: BLE001
                lr = LayerResult(layer=name, status="error")
                lr.add(Diagnostic(
                    tool=name,
                    category=Category.UNKNOWN,
                    severity=Severity.ERROR,
                    message=f"Layer raised exception: {e!r}",
                    layer=name,
                    repairable=False,
                ))
                out[name] = lr
        return out

    @staticmethod
    def _overall_status(layer_results: dict[str, LayerResult], report: VerificationReport) -> str:
        if report.repair and report.repair.self_healed:
            return "verified"
        threshold = Severity(report.layers and "warning" or "warning")
        # If any layer reports fail/error, status is failed
        for r in layer_results.values():
            if r.status in ("fail", "error"):
                return "failed"
        # If any layer has ERROR-severity diagnostics, failed
        for r in layer_results.values():
            for d in r.diagnostics:
                if d.severity == Severity.ERROR:
                    return "failed"
        return "verified"

    @staticmethod
    def _collect_tool_versions() -> dict[str, str]:
        import subprocess
        out = {}
        for tool in ("bash", "shellcheck", "shfmt", "bats", "docker", "python3", "node"):
            try:
                p = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=3)
                v = (p.stdout or p.stderr or "").strip().splitlines()[0] if p.stdout or p.stderr else ""
                out[tool] = v[:120]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                out[tool] = "missing"
        return out

    @staticmethod
    def _redact_metadata(report: VerificationReport) -> None:
        for r in report.layers.values():
            md = r.metadata
            for k, v in list(md.items()):
                if isinstance(v, str):
                    md[k] = redact_secrets(v)
                elif isinstance(v, dict):
                    md[k] = {kk: redact_secrets(vv) if isinstance(vv, str) else vv for kk, vv in v.items()}
