#!/usr/bin/env python3
"""safe_cli_audit.py - CLI subcommands for the audit subsystem.

Invoked as a separate command by the safe-cli wrapper when argv[1]
is "audit", "backlog", or "session". This module is self-bootstrapping:
it adds the package root to sys.path so bv.* imports work without
requiring the caller to set PYTHONPATH.

Subcommands (first argument selects the group):

    backlog list                          List all backlog items
    backlog show <id>                     Show one item
    backlog add --id ID --title T [...]   Create a new item
    backlog start <id>                    Transition item to IN_PROGRESS
    backlog complete <id>                 Transition item to COMPLETE
    backlog next                          Highest-priority ready item
    backlog graph                         Dependency tree

    audit recent [--limit N]              Most recent ledger events
    audit show <session_id>               Events for one session
    audit verify                          Verify the hash chain
    audit events                          All events as one-line summaries
    audit session-report [<session_id>]   Human-readable session report

    session start [--label LABEL]         Begin a session
    session end <session_id>              End a session
    session list                          List known session ids

Common options (place after the group, e.g. `backlog --format json list`):

    --format {text,json}   Output format (default: text)
    --audit-dir PATH       Path to .audit (default: ./.audit)

Exit codes: 0 on success, 1 on error.

The module deliberately uses lazy imports for bv.audit submodules so
that a missing session.py / events.py / formatter.py (the audit
package is being assembled incrementally) does not prevent the rest
of the CLI from working. Commands that depend on a missing module
fail with a clear "not available in this build" message and exit 1.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

# Self-bootstrap: add the package root so bv.* imports resolve.
# /opt/safe-cli-repo/bin/safe_cli_audit.py  ->  parent.parent = /opt/safe-cli-repo
PKG_ROOT = Path(__file__).resolve().parent.parent
if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))


# --------------------------------------------------------------------------- #
# Path helpers                                                                #
# --------------------------------------------------------------------------- #

def _resolve_audit_dir(audit_dir_opt: Optional[str]) -> Path:
    """Resolve the audit directory; default to <cwd>/.audit."""
    if audit_dir_opt:
        return Path(audit_dir_opt).resolve()
    return (Path.cwd() / ".audit").resolve()


# --------------------------------------------------------------------------- #
# Output helpers                                                              #
# --------------------------------------------------------------------------- #

def _emit_json(obj: Any, stream=None) -> None:
    """Emit `obj` as pretty-printed JSON to stream (default stdout)."""
    s = stream or sys.stdout
    s.write(json.dumps(obj, indent=2, default=str, ensure_ascii=False))
    s.write("\n")


def _scalar(v: Any) -> Any:
    """Coerce a dataclass field value into something json.dumps can handle."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, list):
        return [_scalar(x) for x in v]
    if isinstance(v, dict):
        return {k: _scalar(val) for k, val in v.items()}
    if hasattr(v, "value"):  # Enum
        return v.value
    return str(v)


def _to_dict(obj: Any) -> dict:
    """Convert a dataclass instance to a JSON-safe dict."""
    if not (dataclasses.is_dataclass(obj) and not isinstance(obj, type)):
        return {"value": _scalar(obj)}
    out = {}
    for f in dataclasses.fields(obj):
        out[f.name] = _scalar(getattr(obj, f.name))
    return out


def _err(msg: str) -> None:
    """Write an error message to stderr (single line)."""
    sys.stderr.write(f"error: {msg}\n")
    sys.stderr.flush()


# --------------------------------------------------------------------------- #
# Safe Backlog loader                                                         #
# --------------------------------------------------------------------------- #

_BACKLOG_VALID_FIELDS: Optional[set[str]] = None


def _backlog_valid_fields() -> set[str]:
    """Return the set of field names defined on BacklogItem."""
    global _BACKLOG_VALID_FIELDS
    if _BACKLOG_VALID_FIELDS is None:
        from bv.audit.model import BacklogItem
        _BACKLOG_VALID_FIELDS = {f.name for f in dataclasses.fields(BacklogItem)}
    return _BACKLOG_VALID_FIELDS


def _safe_load_items(path: Path) -> list:
    """Read backlog.json and yield BacklogItem instances, dropping any
    fields the dataclass does not know about and coercing priority/
    status strings into their enum types. This keeps the loader
    robust against forward-compatibility fields (e.g. "reason") that
    the strict BacklogItem(**v) constructor would otherwise reject,
    and against raw string values from JSON which the dataclass does
    not auto-coerce.
    """
    if not path.exists():
        return []
    try:
        from bv.audit.model import BacklogItem, BacklogStatus, Priority
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    valid = _backlog_valid_fields()
    items = []
    for v in data.get("items", {}).values():
        filtered = {kk: vv for kk, vv in v.items() if kk in valid}
        # Coerce enum fields from raw JSON strings.
        if isinstance(filtered.get("priority"), str):
            try:
                filtered["priority"] = Priority(filtered["priority"])
            except ValueError:
                pass
        if isinstance(filtered.get("status"), str):
            try:
                filtered["status"] = BacklogStatus(filtered["status"])
            except ValueError:
                pass
        try:
            items.append(BacklogItem(**filtered))
        except Exception:
            continue
    return items


class _BacklogAdapter:
    """Adapt Backlog so it tolerates forward-compatibility fields.

    If the on-disk backlog.json loads cleanly into Backlog(), we use
    it directly. If BacklogError is raised (typically because some
    item contains a field BacklogItem does not know about), we write
    a sanitized shadow copy next to the real file, load Backlog from
    that, and on every mutation mirror the shadow back to the real
    path. The original file is never destructively rewritten: we copy
    over it only after a successful Backlog save.
    """

    def __init__(self, real_path: Path):
        self.real_path = Path(real_path)
        self._shadow_path: Optional[Path] = None
        self._impl = self._build()

    def _build(self):
        from bv.audit.backlog import Backlog, BacklogError
        try:
            return Backlog(self.real_path)
        except BacklogError:
            pass
        # Build a sanitized shadow file
        valid = _backlog_valid_fields()
        try:
            data = json.loads(self.real_path.read_text(encoding="utf-8"))
        except Exception:
            data = {"items": {}}
        for k, v in list(data.get("items", {}).items()):
            data["items"][k] = {kk: vv for kk, vv in v.items() if kk in valid}
        shadow = self.real_path.with_name(self.real_path.name + ".cleaned")
        shadow.write_text(
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        self._shadow_path = shadow
        from bv.audit.backlog import Backlog
        return Backlog(shadow)

    def _flush(self) -> None:
        """Copy the shadow back to the real path after a successful save."""
        if self._shadow_path is not None and self._shadow_path.exists():
            shutil.copy2(self._shadow_path, self.real_path)

    def all(self):
        return self._impl.all()

    def get(self, item_id):
        return self._impl.get(item_id)

    def next(self):
        return self._impl.next()

    def transition(self, item_id, to, note=""):
        result = self._impl.transition(item_id, to, note)
        self._flush()
        return result

    def add(self, item):
        result = self._impl.add(item)
        self._flush()
        return result


# --------------------------------------------------------------------------- #
# backlog subcommands                                                         #
# --------------------------------------------------------------------------- #

def cmd_backlog_list(args) -> int:
    audit_dir = _resolve_audit_dir(args.audit_dir)
    items = _safe_load_items(audit_dir / "backlog.json")
    if args.format == "json":
        _emit_json({"items": [_to_dict(i) for i in items]})
        return 0
    if not items:
        print("no items")
        return 0
    items.sort(key=lambda i: (i.priority.value, i.id))
    for i in items:
        title = (i.title or "").replace("\n", " ")
        print(f"{i.id:8} [{i.status.value:18}] [{i.priority.value}] {title}")
    return 0


def cmd_backlog_show(args) -> int:
    audit_dir = _resolve_audit_dir(args.audit_dir)
    items = {i.id: i for i in _safe_load_items(audit_dir / "backlog.json")}
    item = items.get(args.id)
    if item is None:
        _err(f"unknown backlog item: {args.id}")
        return 1
    if args.format == "json":
        _emit_json(_to_dict(item))
        return 0
    print(f"id:          {item.id}")
    print(f"title:       {item.title}")
    print(f"status:      {item.status.value}")
    print(f"priority:    {item.priority.value}")
    if item.category:
        print(f"category:    {item.category}")
    if item.description:
        print(f"description: {item.description}")
    print(f"created:     {item.created_at}")
    print(f"updated:     {item.updated_at}")
    if item.started_at:
        print(f"started:     {item.started_at}")
    if item.completed_at:
        print(f"completed:   {item.completed_at}")
    if item.dependencies:
        print(f"depends_on:  {', '.join(item.dependencies)}")
    if item.blocked_by:
        print(f"blocked_by:  {', '.join(item.blocked_by)}")
    return 0


def cmd_backlog_add(args) -> int:
    from bv.audit.model import BacklogItem, BacklogStatus, Priority
    audit_dir = _resolve_audit_dir(args.audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    item = BacklogItem(
        id=args.id,
        title=args.title,
        description=args.description or "",
        priority=Priority(args.priority),
        status=BacklogStatus.BACKLOG,
        category=args.category or "",
    )
    bl = _BacklogAdapter(audit_dir / "backlog.json")
    try:
        bl.add(item)
    except Exception as e:
        _err(str(e))
        return 1
    if args.format == "json":
        _emit_json(_to_dict(item))
    else:
        print(f"added: {item.id}")
    return 0


def _cmd_transition(args, to_status: str, label: str) -> int:
    from bv.audit.model import BacklogStatus
    audit_dir = _resolve_audit_dir(args.audit_dir)
    bl = _BacklogAdapter(audit_dir / "backlog.json")
    try:
        item = bl.transition(args.id, BacklogStatus(to_status), note=args.note or "")
    except Exception as e:
        _err(str(e))
        return 1
    if args.format == "json":
        _emit_json(_to_dict(item))
    else:
        print(f"{label}: {item.id} -> {item.status.value}")
    return 0


def cmd_backlog_start(args) -> int:
    from bv.audit.model import BacklogStatus
    return _cmd_transition(args, BacklogStatus.IN_PROGRESS.value, "started")


def cmd_backlog_complete(args) -> int:
    from bv.audit.model import BacklogStatus
    return _cmd_transition(args, BacklogStatus.COMPLETE.value, "completed")


def cmd_backlog_next(args) -> int:
    audit_dir = _resolve_audit_dir(args.audit_dir)
    bl = _BacklogAdapter(audit_dir / "backlog.json")
    item = bl.next()
    if item is None:
        if args.format == "json":
            _emit_json({"next": None})
        else:
            print("no next item")
        return 0
    if args.format == "json":
        _emit_json({"next": _to_dict(item)})
    else:
        print(f"{item.id} [{item.priority.value}] {item.title}")
    return 0


def cmd_backlog_graph(args) -> int:
    """Print the dependency graph as an indented tree.

    Each item lists its dependencies (depends_on). The CLI inverts
    those into a children map and walks from the roots (items whose
    dependencies are not in the set, plus items with no dependencies
    that nothing references). Items not reachable from a root are
    printed as orphans.
    """
    audit_dir = _resolve_audit_dir(args.audit_dir)
    items = _safe_load_items(audit_dir / "backlog.json")
    if not items:
        if args.format == "json":
            _emit_json({"nodes": []})
        else:
            print("no items")
        return 0
    if args.format == "json":
        nodes = [
            {"id": i.id, "title": i.title, "depends_on": list(i.dependencies)}
            for i in items
        ]
        _emit_json({"nodes": nodes})
        return 0
    item_ids = {i.id for i in items}
    children_of: dict[str, list[str]] = {}
    for i in items:
        for dep in i.dependencies:
            children_of.setdefault(dep, []).append(i.id)
    roots = [
        i for i in items
        if not i.dependencies or not (set(i.dependencies) & item_ids)
    ]
    visited: set[str] = set()

    def _walk(node_id: str, depth: int) -> None:
        if node_id in visited:
            print("  " * depth + f"{node_id} (cycle)")
            return
        visited.add(node_id)
        item = next((x for x in items if x.id == node_id), None)
        title = item.title if item else ""
        line = f"{node_id}" + (f"  {title}" if title else "")
        print("  " * depth + line)
        for child in sorted(children_of.get(node_id, [])):
            _walk(child, depth + 1)

    for r in sorted(roots, key=lambda i: i.id):
        _walk(r.id, 0)
    orphans = [i for i in items if i.id not in visited]
    for o in sorted(orphans, key=lambda i: i.id):
        deps_in_set = [d for d in o.dependencies if d in item_ids]
        print(f"{o.id}  {o.title}  (orphan: deps={deps_in_set})")
    return 0


# --------------------------------------------------------------------------- #
# audit subcommands                                                           #
# --------------------------------------------------------------------------- #

def _event_line(e: Any) -> str:
    """Render an Event as one line."""
    ts = (e.timestamp or "?")[:19]
    et = e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)
    sev = e.severity.value if hasattr(e.severity, "value") else str(e.severity)
    msg = (e.message or "").replace("\n", " ")
    return f"{ts} {e.session_id:24} {sev:8} {et:30} {(e.component or ''):12} {msg}"


def cmd_audit_recent(args) -> int:
    from bv.audit.reader import AuditReader
    audit_dir = _resolve_audit_dir(args.audit_dir)
    reader = AuditReader(audit_dir / "events.jsonl")
    events = list(reader.iter_events())
    if args.limit and args.limit > 0:
        events = events[-args.limit:]
    if args.format == "json":
        _emit_json({"events": [_to_dict(e) for e in events]})
        return 0
    if not events:
        print("no events")
        return 0
    for e in events:
        print(_event_line(e))
    return 0


def cmd_audit_show(args) -> int:
    from bv.audit.reader import AuditReader
    audit_dir = _resolve_audit_dir(args.audit_dir)
    reader = AuditReader(audit_dir / "events.jsonl")
    events = reader.find_session(args.session_id)
    if args.format == "json":
        _emit_json({"session_id": args.session_id, "events": [_to_dict(e) for e in events]})
        return 0
    if not events:
        print(f"no events for session: {args.session_id}")
        return 0
    for e in events:
        print(_event_line(e))
    return 0


def cmd_audit_verify(args) -> int:
    from bv.audit.reader import verify_chain
    audit_dir = _resolve_audit_dir(args.audit_dir)
    report = verify_chain(audit_dir / "events.jsonl")
    if args.format == "json":
        _emit_json(report)
    else:
        status = "OK" if report.get("ok") else "FAIL"
        print(f"verify: {status}")
        print(f"  total events: {report.get('total', 0)}")
        if report.get("duplicates"):
            print(f"  duplicates:   {len(report['duplicates'])}")
        if report.get("broken_chain"):
            print(f"  broken_chain: {len(report['broken_chain'])}")
        if report.get("malformed"):
            print(f"  malformed:    {len(report['malformed'])}")
        if report.get("missing_fields"):
            print(f"  missing:      {len(report['missing_fields'])}")
    return 0 if report.get("ok") else 1


def cmd_audit_events(args) -> int:
    """Print every event as a one-line summary."""
    from bv.audit.reader import AuditReader
    audit_dir = _resolve_audit_dir(args.audit_dir)
    reader = AuditReader(audit_dir / "events.jsonl")
    events = list(reader.iter_events())
    if args.format == "json":
        _emit_json({"events": [_to_dict(e) for e in events]})
        return 0
    if not events:
        print("no events")
        return 0
    for e in events:
        print(_event_line(e))
    return 0


def cmd_audit_session_report(args) -> int:
    """Render a human session report via bv.audit.formatter."""
    from bv.audit.reader import AuditReader
    audit_dir = _resolve_audit_dir(args.audit_dir)
    reader = AuditReader(audit_dir / "events.jsonl")
    events = list(reader.iter_events())
    if args.session_id:
        events = [e for e in events if e.session_id == args.session_id]
    try:
        from bv.audit.formatter import human_session_report
    except ImportError:
        _err("bv.audit.formatter is not available in this build")
        return 1
    report = human_session_report(events)
    if args.format == "json":
        _emit_json({"report": _scalar(report)})
        return 0
    sys.stdout.write(report if isinstance(report, str) else str(report))
    if not str(report).endswith("\n"):
        sys.stdout.write("\n")
    return 0


# --------------------------------------------------------------------------- #
# session subcommands                                                         #
# --------------------------------------------------------------------------- #

def _audit_directory_from(audit_dir: Path):
    """Build an AuditDirectory rooted at the parent of .audit.

    The audit subsystem's convention is that the directory passed in
    *is* .audit itself, but AuditDirectory expects its parent and
    appends '.audit' on construction. We accept both shapes.
    """
    from bv.audit.writer import AuditDirectory
    if audit_dir.name == ".audit":
        return AuditDirectory(audit_dir.parent)
    return AuditDirectory(audit_dir)


def cmd_session_start(args) -> int:
    try:
        from bv.audit.session import Session
    except ImportError:
        _err("bv.audit.session is not available in this build")
        return 1
    audit_dir = _resolve_audit_dir(args.audit_dir)
    ad = _audit_directory_from(audit_dir)
    try:
        s = Session.start(ad, label=args.label or "")
    except Exception as e:
        _err(str(e))
        return 1
    if args.format == "json":
        _emit_json({"session_id": getattr(s, "session_id", None), "status": "started"})
    else:
        print(f"session started: {getattr(s, 'session_id', '?')}")
    return 0


def cmd_session_end(args) -> int:
    try:
        from bv.audit.session import Session
    except ImportError:
        _err("bv.audit.session is not available in this build")
        return 1
    audit_dir = _resolve_audit_dir(args.audit_dir)
    ad = _audit_directory_from(audit_dir)
    try:
        Session.end(ad, session_id=args.session_id)
    except Exception as e:
        _err(str(e))
        return 1
    if args.format == "json":
        _emit_json({"session_id": args.session_id, "status": "ended"})
    else:
        print(f"session ended: {args.session_id}")
    return 0


def cmd_session_list(args) -> int:
    """List known session ids, derived from the event ledger.

    Session ids that have not yet emitted any event will not appear.
    This is intentional: the audit ledger is the source of truth.
    """
    from bv.audit.reader import AuditReader
    audit_dir = _resolve_audit_dir(args.audit_dir)
    reader = AuditReader(audit_dir / "events.jsonl")
    ids = sorted({e.session_id for e in reader.iter_events() if e.session_id})
    if args.format == "json":
        _emit_json({"sessions": ids})
        return 0
    if not ids:
        print("no sessions")
        return 0
    for sid in ids:
        print(sid)
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing                                                            #
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safe-cli audit|backlog|session",
        description=(
            "CLI for the safe-cli audit subsystem: "
            "backlog state, event ledger, sessions."
        ),
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--audit-dir", default=None,
        help="Path to .audit (default: <cwd>/.audit)",
    )
    sub = parser.add_subparsers(dest="group", required=True)

    # ----- backlog ----- #
    bl = sub.add_parser("backlog")
    bl_sub = bl.add_subparsers(dest="cmd", required=True)

    p = bl_sub.add_parser("list")
    p.set_defaults(func=cmd_backlog_list)

    p = bl_sub.add_parser("show")
    p.add_argument("id")
    p.set_defaults(func=cmd_backlog_show)

    p = bl_sub.add_parser("add")
    p.add_argument("--id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--description", default="")
    p.add_argument(
        "--priority", default="P1", choices=["P0", "P1", "P2", "P3"],
    )
    p.add_argument("--category", default="")
    p.set_defaults(func=cmd_backlog_add)

    p = bl_sub.add_parser("start")
    p.add_argument("id")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_backlog_start)

    p = bl_sub.add_parser("complete")
    p.add_argument("id")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_backlog_complete)

    p = bl_sub.add_parser("next")
    p.set_defaults(func=cmd_backlog_next)

    p = bl_sub.add_parser("graph")
    p.set_defaults(func=cmd_backlog_graph)

    # ----- audit ----- #
    au = sub.add_parser("audit")
    au_sub = au.add_subparsers(dest="cmd", required=True)

    p = au_sub.add_parser("recent")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_audit_recent)

    p = au_sub.add_parser("show")
    p.add_argument("session_id")
    p.set_defaults(func=cmd_audit_show)

    p = au_sub.add_parser("verify")
    p.set_defaults(func=cmd_audit_verify)

    p = au_sub.add_parser("events")
    p.set_defaults(func=cmd_audit_events)

    p = au_sub.add_parser("session-report")
    p.add_argument("session_id", nargs="?")
    p.set_defaults(func=cmd_audit_session_report)

    # ----- session ----- #
    se = sub.add_parser("session")
    se_sub = se.add_subparsers(dest="cmd", required=True)

    p = se_sub.add_parser("start")
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_session_start)

    p = se_sub.add_parser("end")
    p.add_argument("session_id")
    p.set_defaults(func=cmd_session_end)

    p = se_sub.add_parser("list")
    p.set_defaults(func=cmd_session_list)

    return parser


def _extract_global_opts(argv: list[str]) -> tuple[list[str], dict]:
    """Pull --format and --audit-dir out of argv so they can appear in
    any position. Returns (cleaned_argv, overrides)."""
    overrides: dict[str, str] = {}
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--format" and i + 1 < len(argv):
            overrides["format"] = argv[i + 1]
            i += 2
            continue
        if a.startswith("--format="):
            overrides["format"] = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--audit-dir" and i + 1 < len(argv):
            overrides["audit_dir"] = argv[i + 1]
            i += 2
            continue
        if a.startswith("--audit-dir="):
            overrides["audit_dir"] = a.split("=", 1)[1]
            i += 1
            continue
        out.append(a)
        i += 1
    if overrides:
        # Re-inject at the front so the parent parser picks them up.
        prefix: list[str] = []
        if "format" in overrides:
            prefix += ["--format", overrides["format"]]
        if "audit_dir" in overrides:
            prefix += ["--audit-dir", overrides["audit_dir"]]
        out = prefix + out
    return out, overrides


def main(argv: list[str]) -> int:
    """Dispatch on argv[1] (group) and argv[2] (subcommand)."""
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        _build_parser().print_help()
        return 0
    cleaned, _overrides = _extract_global_opts(argv[1:])
    parser = _build_parser()
    args = parser.parse_args(cleaned)
    try:
        rc = args.func(args)
    except KeyboardInterrupt:
        _err("interrupted")
        return 1
    except Exception as e:
        _err(str(e))
        return 1
    return 0 if rc is None else (1 if rc != 0 else 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
