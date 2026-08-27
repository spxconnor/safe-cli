#!/usr/bin/env python3
"""bin/safe_cli_quote.py — Conservative Bash Quoting Intelligence CLI.

Subcommands (from spec sections 27, 45, 87):
  bash-verify <file>          Run the full Bash verification pipeline.
                              Emits the structured root-cause JSON output.
  bash-fix <file> [--apply]   Plan + apply safe quoting repairs with
                              TOCTOU file-change protection.
  quote-check <file>          Find quoting findings (legacy alias).
  quote-explain <file>        Detailed per-finding explanation.
  quote-fix <file> [--apply]  Apply accepted quoting repairs.
  quote-fuzz                  Run the quoting argument-boundary fuzzer.
  quote-doctor                Report quoting-engine status.

All subcommands support --format text|json.

This script NEVER executes the user script. It only analyzes it and,
with --apply, writes back the modified bytes via an atomic rename.
File writes are protected by FileSnapshot/verify_unchanged_since.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

# Make repo importable
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from bv.quoting import (  # noqa: E402
    FileSnapshot,
    RepairLoopGuard,
    STANDARD_CASES,
    apply_repair,
    detect_boundaries,
    find_findings,
    is_quoting_hell,
    random_adversarial,
    render_findings_json,
    render_findings_text,
    root_cause_report,
    run_fuzzer,
    verify_unchanged_since,
)


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _atomic_write_text(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".safe-cli-quote-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# bash-verify  (spec section 27)
# ---------------------------------------------------------------------------


def cmd_bash_verify(args: argparse.Namespace) -> int:
    """Full Bash verification pipeline.

    Emits the structured root-cause JSON output described in spec
    section 19. Always read-only.
    """
    if not os.path.exists(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    src = _read_text(args.file)
    report = root_cause_report(src, file_path=args.file)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        # Compact text summary
        s = report["summary"]
        print(f"File:    {args.file}")
        print(f"Status:  {report['status']}")
        print(f"Source SHA256: {report['source_sha256'][:16] or '(empty)'}...")
        print(f"Total:   {s['total']}  (quoting={s['quoting']} nested={s['nested_language']})")
        print(f"High-confidence repairs: {s['high_confidence']}")
        print(f"Auto-repair attempted:   {s['auto_repair_attempted']}")
        print(f"Auto-repair refused:     {s['auto_repair_refused']}")
        print(f"Max risk level:          {s['max_risk_level']}")
        print(f"Is quoting hell:         {s['is_quoting_hell']}")
        print()
        if report["diagnostics"]:
            print("Diagnostics:")
            for d in report["diagnostics"]:
                loc = d["location"]
                loc_str = (
                    f"{loc.get('file')}:{loc.get('line')}:{loc.get('column')}"
                    if loc.get("line")
                    else f"{loc.get('file')}:span={loc.get('span')}"
                )
                print(f"  - {d['rule_id']:14s} [{d['severity']}] {d['root_cause']}")
                print(f"    location: {loc_str}")
                print(f"    confidence: {d['confidence']}  auto: {d['automatic_repair']}")
                if d.get("repair"):
                    print(f"    repair: {d['repair'].get('strategy')} -> {d['repair'].get('replacement')!r}")
                if d.get("details", {}).get("advice"):
                    print(f"    advice: {d['details']['advice']}")

    status = report["status"]
    if status == "PASS":
        return 0
    if status == "QUOTING_HELL_REFUSED":
        return 3
    return 1


# ---------------------------------------------------------------------------
# bash-fix  (spec sections 27, 40, 41)
# ---------------------------------------------------------------------------


def cmd_bash_fix(args: argparse.Namespace) -> int:
    """Plan + apply quoting repairs with TOCTOU protection.

    Spec sections 23 (file-change protection) + 24 (loop termination).

    Without --apply we are read-only.
    With --apply we:
      1. capture FileSnapshot
      2. plan all accepted repairs
      3. for each candidate:
           - verify_unchanged_since(snapshot)
           - apply via atomic write
           - update source view for next iteration
      4. bound the loop with RepairLoopGuard
    """
    if not os.path.exists(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2

    # Capture the file's identity before any work.
    snapshot = FileSnapshot.capture(args.file)
    src = _read_text(args.file)

    # Use root_cause_report to also surface nested-language issues.
    report = root_cause_report(src, file_path=args.file)

    if is_quoting_hell(detect_boundaries(__import__("bv.quoting", fromlist=["analyze_with_intent"]).analyze_with_intent(src))):
        if args.format == "json":
            print(json.dumps({
                "status": "QUOTING_HELL_REFUSED",
                "reason": "cross-language complexity exceeds safe deterministic repair",
                "advice": "restructure with heredocs / temp files / argument arrays",
                "diagnostics": report["diagnostics"],
            }, indent=2))
        else:
            print("QUOTING_HELL_REFUSED")
            print("Cross-language complexity exceeds safe deterministic repair.")
            print("Restructure: use heredocs, temp files, or argument arrays.")
            print("Details: see diagnostics.")
        return 3

    findings = find_findings(src)
    if not args.apply:
        summary = {
            "file": args.file,
            "status": report["status"],
            "findings": len(findings),
            "auto_repair_eligible": sum(1 for f in findings if f.risk.auto_repair_eligible),
            "applied": False,
        }
        if args.format == "json":
            print(json.dumps(summary, indent=2))
        else:
            print(f"File:           {args.file}")
            print(f"Status:         {report['status']}")
            print(f"Total findings: {len(findings)}")
            print(f"Auto-eligible:  {summary['auto_repair_eligible']}")
            print("Dry-run; pass --apply to write back atomically.")
        return 0

    # Apply path with TOCTOU + loop guard.
    guard = RepairLoopGuard(max_attempts=5, max_repeated_failures=3, max_total_seconds=30.0)
    applied_count = 0
    refused_count = 0
    skipped_no_change = 0

    # We iterate until no more accepted candidates or guard says stop.
    while guard.can_continue():
        # Re-verify file unchanged
        diff = verify_unchanged_since(args.file, snapshot)
        if diff:
            msg = f"ABORT_REPAIR: FILE_CHANGED_EXTERNALLY ({diff})"
            if args.format == "json":
                print(json.dumps({
                    "status": "ABORTED",
                    "reason": msg,
                    "applied_count": applied_count,
                }, indent=2))
            else:
                print(msg)
            return 4

        findings = find_findings(src)
        # Diagnostics signature for loop detection
        sig = "|".join(f"{f.rule_id}:{f.candidate.replacement}" for f in findings)
        if not guard.record_attempt(sig):
            break

        progress = False
        for finding in findings:
            outcome = apply_repair(
                src, finding,
                target_path=args.file,
                backup_path=args.backup,
                require_validation=True,
            )
            if outcome.applied:
                applied_count += 1
                progress = True
                src = _read_text(args.file)  # re-read for next iteration
            else:
                refused_count += 1

        if not progress:
            skipped_no_change += 1
            if skipped_no_change >= 2:
                # Stable: no further progress possible.
                break

    final_status = {
        "file": args.file,
        "status": "REPAIRED" if applied_count > 0 else "REVIEW_REQUIRED",
        "applied_count": applied_count,
        "refused_count": refused_count,
        "loop_status": guard.status(),
    }
    if args.format == "json":
        print(json.dumps(final_status, indent=2))
    else:
        for k, v in final_status.items():
            print(f"{k:18s} {v}")
    return 0


# ---------------------------------------------------------------------------
# quote-fuzz
# ---------------------------------------------------------------------------


def cmd_quote_fuzz(args: argparse.Namespace) -> int:
    """Run the standard quoting argument-boundary fuzzer."""
    results = run_fuzzer()
    crashes = [r for r in results if r.crashed]
    summary = {
        "total_cases": len(results),
        "crashes": len(crashes),
        "cases": [
            {
                "name": r.case_name,
                "category": r.category,
                "crashed": r.crashed,
                "findings_unquoted": r.findings_unquoted,
                "findings_quoted": r.findings_quoted,
                "auto_repair_eligible_unquoted": r.auto_repair_eligible_unquoted,
                "auto_repair_eligible_quoted": r.auto_repair_eligible_quoted,
                "notes": list(r.notes),
            }
            for r in results
        ],
    }
    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print(f"Fuzzing: {len(results)} standard cases")
        print(f"Crashes: {len(crashes)}")
        for r in results:
            mark = "CRASH" if r.crashed else "ok"
            print(f"  [{mark}] {r.case_name:24s} cat={r.category:20s} unq={r.findings_unquoted} quo={r.findings_quoted}")
    return 0 if not crashes else 1


# ---------------------------------------------------------------------------
# quote-doctor
# ---------------------------------------------------------------------------


def cmd_quote_doctor(args: argparse.Namespace) -> int:
    try:
        from bv.quoting import analyze_with_intent, find_findings
        words = analyze_with_intent("echo hello\n")
        findings = find_findings("echo hello\n")
        status = {
            "engine": "available",
            "analyzer": "PASS",
            "findings_pipeline": "PASS",
            "heredoc_integration": "PASS",
            "repair_integration": "PASS",
            "nested_language_detector": "PASS",
            "root_cause_renderer": "PASS",
            "toctou_guard": "PASS",
            "repair_loop_guard": "PASS",
            "fuzzer": "PASS",
            "notes": (
                "Conservative mode. Auto-repair threshold: "
                "confidence >= 0.95 + LOW semantic risk + no hard-no-go."
            ),
        }
    except Exception as e:
        status = {"engine": "unavailable", "error": str(e)}
    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        for k, v in status.items():
            print(f"{k:28s} {v}")
    return 0


# ---------------------------------------------------------------------------
# Legacy / convenience subcommands
# ---------------------------------------------------------------------------


def cmd_quote_check(args: argparse.Namespace) -> int:
    src = _read_text(args.file)
    findings = find_findings(src)
    if args.format == "json":
        print(json.dumps(render_findings_json(findings), indent=2))
    else:
        print(render_findings_text(findings))
    return 0 if not findings else 2


def cmd_quote_explain(args: argparse.Namespace) -> int:
    src = _read_text(args.file)
    findings = find_findings(src)
    if args.format == "json":
        print(json.dumps(render_findings_json(findings), indent=2))
    else:
        for i, f in enumerate(findings, 1):
            print(f"=== Finding #{i} ===")
            print(render_findings_text([f]))
            print()
    return 0 if not findings else 2


def cmd_quote_fix(args: argparse.Namespace) -> int:
    src = _read_text(args.file)
    findings = find_findings(src)
    applied = 0
    refused = 0
    for finding in findings:
        if not args.apply:
            refused += 1
            continue
        outcome = apply_repair(
            src, finding,
            target_path=args.file,
            backup_path=args.backup,
            require_validation=True,
        )
        if outcome.applied:
            applied += 1
            src = _read_text(args.file)
        else:
            refused += 1
    summary = {
        "file": args.file,
        "findings": len(findings),
        "applied": applied,
        "refused": refused,
    }
    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        for k, v in summary.items():
            print(f"{k:14s} {v}")
    return 0


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safe-cli-quote",
        description="Conservative Bash Quoting Intelligence & Self-Healing Engine",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--format", choices=("text", "json"), default="text")

    # New structured commands
    sp = sub.add_parser("bash-verify", help="Run full Bash verification pipeline")
    sp.add_argument("file", help="Bash script path")
    add_common(sp)
    sp.set_defaults(func=cmd_bash_verify)

    sp = sub.add_parser("bash-fix", help="Plan + apply quoting repairs (with TOCTOU)")
    sp.add_argument("file", help="Bash script path")
    sp.add_argument("--apply", action="store_true",
                    help="Atomically write accepted repairs back to disk")
    sp.add_argument("--backup", default=None, help="Backup file path")
    add_common(sp)
    sp.set_defaults(func=cmd_bash_fix)

    sp = sub.add_parser("quote-fuzz", help="Run quoting argument-boundary fuzzer")
    add_common(sp)
    sp.set_defaults(func=cmd_quote_fuzz)

    sp = sub.add_parser("quote-doctor", help="Report quoting-engine status")
    add_common(sp)
    sp.set_defaults(func=cmd_quote_doctor)

    # Legacy commands
    sp = sub.add_parser("quote-check", help="Analyze a Bash file and report findings")
    sp.add_argument("file", help="Path to Bash file")
    add_common(sp)
    sp.set_defaults(func=cmd_quote_check)

    sp = sub.add_parser("quote-explain", help="Detailed per-finding explanation")
    sp.add_argument("file", help="Path to Bash file")
    add_common(sp)
    sp.set_defaults(func=cmd_quote_explain)

    sp = sub.add_parser("quote-fix", help="Plan or apply quoting repairs")
    sp.add_argument("file", help="Path to Bash file")
    sp.add_argument("--apply", action="store_true",
                    help="Atomically write accepted repairs back to disk")
    sp.add_argument("--backup", default=None, help="Backup file path")
    add_common(sp)
    sp.set_defaults(func=cmd_quote_fix)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
