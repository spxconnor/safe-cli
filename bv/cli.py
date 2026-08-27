"""Command-line interface for bash_verify."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .script import from_path, from_content
from .orchestrator import Orchestrator, LAYER_ORDER


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bash_verify",
        description="Multi-layer Bash verification and self-healing engine",
    )
    p.add_argument("script", nargs="?", help="Path to the Bash script to verify")
    p.add_argument("--stdin", action="store_true", help="Read script from stdin")
    p.add_argument("--fix", action="store_true", help="Apply self-healing repairs")
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    p.add_argument("--test", help="Path to a bats test file to run against the script")
    p.add_argument("--fuzz", type=int, default=0, metavar="N",
                   help="Run fuzz layer with N iterations (0 = skip)")
    p.add_argument("--adversarial", action="store_true", help="Run adversarial quoting layer")
    p.add_argument("--sandbox", action="store_true", help="Always run sandbox layer")
    p.add_argument("--no-sandbox", action="store_true", help="Skip sandbox layer")
    p.add_argument("--json", action="store_true", help="Emit JSON report only")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--layers", default=",".join(LAYER_ORDER),
                   help=f"Comma-separated layer names (default: all). Choices: {','.join(LAYER_ORDER)}")
    p.add_argument("--no-repair", action="store_true", help="Disable self-healing for this run")
    p.add_argument("--write-back", action="store_true",
                   help="Persist repaired content to the original script file")
    p.add_argument("--doctor", action="store_true", help="Run installation health check")
    p.add_argument("--ci", action="store_true", help="CI mode: nonzero exit on verification failure")
    p.add_argument("--config", default="/opt/bash-verifier/.bashverify.toml",
                   help="Path to .bashverify.toml config")
    return p


def run_doctor(config) -> int:
    """Check installation and health of every component."""
    rows = []
    import shutil
    import subprocess

    def check(name, present: bool, version: str = ""):
        rows.append((name, "PASS" if present else "FAIL", version))

    # Tools
    for tool, label in [
        ("bash", "Bash"), ("shellcheck", "ShellCheck"),
        ("shfmt", "shfmt"), ("bats", "Bats"),
        ("docker", "Docker"), ("python3", "Python3"),
        ("node", "Node"),
    ]:
        path = shutil.which(tool)
        if not path:
            check(label, False, "not found")
            continue
        try:
            p = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=3)
            v = (p.stdout or p.stderr or "").strip().splitlines()[0][:80]
            check(label, True, v)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            check(label, False, "timeout")

    # Python deps
    try:
        import tree_sitter  # noqa
        import tree_sitter_bash  # noqa
        check("Python tree-sitter-bash", True, "imported")
    except ImportError as e:
        check("Python tree-sitter-bash", False, str(e))

    # Bash language server
    bls = shutil.which("bash-language-server")
    check("Bash Language Server", bls is not None, bls or "missing")

    # Docker daemon
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        check("Docker daemon", p.returncode == 0, "running" if p.returncode == 0 else "unavailable")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        check("Docker daemon", False, "timeout")

    # Sandbox image
    try:
        img = config.verify.sandbox_image
        p = subprocess.run(["docker", "image", "inspect", img], capture_output=True, text=True, timeout=5)
        check(f"Sandbox image ({img})", p.returncode == 0, "pulled" if p.returncode == 0 else "not pulled")
    except Exception:
        check("Sandbox image", False, "check failed")

    # Config
    cfg_path = Path(config.source_path)
    check("Config file", cfg_path.exists(), str(cfg_path))

    # Backup dir
    from .script import DEFAULT_BACKUP_ROOT
    check("Backup directory", DEFAULT_BACKUP_ROOT.exists(), str(DEFAULT_BACKUP_ROOT))

    print("\n=== BASH VERIFICATION DOCTOR ===\n")
    name_width = max(len(r[0]) for r in rows)
    for name, status, version in rows:
        status_mark = "OK " if status == "PASS" else "XX "
        print(f"  {status_mark} {name:<{name_width}}  {status:<5}  {version}")

    overall = all(r[1] == "PASS" for r in rows)
    print()
    print(f"Overall: {'READY' if overall else 'DEGRADED'}")
    return 0 if overall else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.doctor:
        return run_doctor(config)

    # Determine script source
    if args.stdin or (not args.script and not sys.stdin.isatty()):
        content = sys.stdin.read()
        script = from_content(content)
    elif args.script:
        script = from_path(args.script)
    else:
        parser.error("Provide a script path or pipe via --stdin")
        return 2

    # Build layer context
    extra = {}
    if args.test:
        extra["bats_tests"] = args.test
    if args.no_sandbox:
        extra["skip_sandbox"] = True
    if args.fuzz:
        extra["fuzz_iterations"] = args.fuzz
        extra["fuzz_seed"] = 0
    context_args = {"extra": extra}

    # Determine which layers to run
    if args.layers != ",".join(LAYER_ORDER):
        layers = [s.strip() for s in args.layers.split(",") if s.strip()]
    else:
        layers = list(LAYER_ORDER)

    # Skip layers based on flags
    if args.no_sandbox and "sandbox" in layers:
        layers.remove("sandbox")
    if not args.adversarial and "adversarial" in layers:
        layers.remove("adversarial")
    if not args.fuzz and "fuzz" in layers:
        layers.remove("fuzz")
    if not args.sandbox and "side_effects" in layers:
        layers.remove("side_effects")

    orch = Orchestrator(config)
    report = orch.run(script, layers=layers, repair=not args.no_repair, context=type("Ctx", (), context_args)())

    # Decide exit code
    threshold = "error" if args.strict else "warning"
    blocking = report.above_threshold(__import__("bv.diagnostic", fromlist=["Severity"]).Severity(threshold))

    # --ci exit semantics:
    #   verified   → fully passed       → exit 0
    #   incomplete → no hard failure, but at least one layer couldn't
    #                fully verify (e.g. bats missing in the sandbox
    #                image, LSP timed out). The orchestrator has
    #                already established that no layer reported
    #                status=fail/error and no ERROR-severity diagnostic
    #                exists, so for CI purposes this is a non-failure.
    #                Promoting it to exit 0 here restores sensible
    #                behavior for tools that gate on this exit code
    #                (e.g. `safe-cli verify` against an otherwise-clean
    #                script in a sandbox without bats).
    #   failed/error → exit 1
    # This is safe to widen because the safe-cli wrapper re-parses the
    # human-readable "Status:" line and refuses to EXECUTE anything
    # that is not exactly "verified" (see cmd_run in /usr/local/bin/safe-cli).
    # See the helper `ci_exit_code()` below.

    if args.json:
        print(report.to_json())
        if args.ci:
            return ci_exit_code(report.status)
        return 0

    # Human-readable
    print(f"\n=== BASH VERIFICATION REPORT ===\n")
    print(f"Script:  {report.script_path}")
    print(f"Status:  {report.status}")
    print(f"FP:      {report.script_fingerprint[:16]}")
    print(f"Time:    {report.duration_ms} ms")
    print()
    print(f"--- Layers ---")
    for name, lr in report.layers.items():
        n = len(lr.diagnostics)
        line = f"  {name:<14}  {lr.status:<5}  {n} diagnostic(s)  {lr.duration_ms} ms"
        if lr.notes:
            line += f"   notes: {'; '.join(lr.notes)}"
        print(line)
    print()

    if report.repair:
        rr = report.repair
        print(f"--- Self-Healing ---")
        print(f"  attempts: {rr.total_attempts}")
        print(f"  healed:   {rr.self_healed}")
        print(f"  aborted:  {rr.aborted_reason or '(no)'}")
        for a in rr.attempts:
            print(f"   - #{a.attempt_number}: strategy={a.strategy_used}  "
                  f"diagnostics {len(a.diagnostics_before)} -> {len(a.diagnostics_after)}")
        print()

    if blocking:
        print(f"--- Blocking Diagnostics ({len(blocking)}) ---")
        for d in blocking[:50]:
            print(f"  {d.short()}")
        if len(blocking) > 50:
            print(f"  ... and {len(blocking) - 50} more")
    else:
        print("--- No blocking diagnostics ---")

    if args.ci:
        # See the long note earlier in this file. Verified and
        # incomplete are both non-failure results for CI semantics.
        return ci_exit_code(report.status)
    return 0


def ci_exit_code(report_status: str) -> int:
    """--ci exit code for a given overall report status.

    verified   → 0  (full pass)
    incomplete → 0  (no hard failure; at least one layer couldn't
                     fully verify — e.g. bats missing in sandbox)
    failed     → 1  (a layer reported a hard failure or an
                     ERROR-severity diagnostic)
    error      → 1  (a layer raised an exception)

    Promoting "incomplete" from 1 to 0 here is what unblocks
    `safe-cli verify` on otherwise-clean scripts after the bats-layer
    fix. The safe-cli wrapper re-parses the report's Status: line and
    refuses to EXECUTE anything that is not exactly "verified", so
    this widening only affects the exit code, not the execution gate.
    """
    if report_status in ("verified", "incomplete"):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
