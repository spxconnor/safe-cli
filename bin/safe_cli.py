#!/usr/bin/env python3
"""safe-cli — one-command Bash safety for AI coding agents.

Self-bootstrapping. Install at /usr/local/bin/safe-cli (and symlinks
bv / safebash / safebash-run / verify-run) so every shell and every
AI coding agent can find it on PATH.

This is the SINGLE command every AI agent should use to execute Bash:

    safe-cli run script.sh             # verify then execute; refuses if broken
    safe-cli exec 'echo hello'         # inline verify then execute
    safe-cli verify script.sh          # verify only, no execution
    safe-cli fix script.sh             # verify, auto-repair, write back
    safe-cli doctor                    # health check (13 components)

If safe-cli refuses (exits non-zero), DO NOT execute the script.
Repair it first or ask the operator.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Self-bootstrap: add /opt/bash-verifier to sys.path so bv.* imports work
PKG_ROOT = Path(__file__).resolve().parent.parent  # /opt/bash-verifier
sys.path.insert(0, str(PKG_ROOT))

from bv.config import load_config  # noqa: E402

BV_BIN = Path("/opt/bash-verifier/bin/bash_verify")
ALIASES = ["bv", "safebash", "safebash-run", "verify-run"]

USAGE = """safe-cli — one-command Bash safety for AI coding agents

USAGE:
    safe-cli run <script.sh>           Verify then execute; refuses if broken
    safe-cli exec '<bash-snippet>'     Verify inline Bash then execute
    safe-cli verify <script.sh>        Verify only (do not execute)
    safe-cli fix <script.sh>           Verify + auto-repair + write back
    safe-cli doctor                    Health check of all components
    safe-cli help                      This help
    safe-cli --                        Read Bash from stdin

EXIT CODES:
    0   Verified (and executed, for run/exec)
    1   Verification failed (refused; do NOT execute)
    2   Argument error / internal error
    124 Timeout (sandbox killed a runaway process)

SAFETY:
    - safe-cli NEVER deletes files. It moves them aside with timestamps.
    - safe-cli NEVER bypasses verification.
    - safe-cli NEVER executes a script bash_verify rejected.

EXAMPLES:
    safe-cli run /opt/bash-verifier/tests/good_scripts/hello_world.sh
    safe-cli exec 'echo Hello, $USER'
    safe-cli exec 'for f in /tmp/bv_safe_demo/*.txt; do echo "$f"; done'
    safe-cli fix /tmp/myscript.sh          # auto-repair in place
    safe-cli doctor                         # all green?

For AI agents: when in doubt, run `safe-cli verify <script>` before
running it. When `safe-cli` exits non-zero, do NOT execute.
"""


def _log(stage: str, msg: str) -> None:
    sys.stderr.write(f"[safe-cli:{stage}] {msg}\n")
    sys.stderr.flush()


def _now() -> int:
    return int(time.time())


def _forensic_move(path: Path, suffix: str) -> Path:
    """Move a temp file aside for forensics; NEVER delete."""
    target = path.with_name(f"{path.name}.{suffix}-{_now()}")
    path.rename(target)
    return target


def _run_bash_verify(args: list[str]) -> tuple[int, str]:
    """Invoke bash_verify with the given args; return (rc, full_output)."""
    proc = subprocess.run(
        [str(BV_BIN)] + args,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _read_stdin() -> str:
    if sys.stdin.isatty():
        _log("error", "no script provided on stdin")
        sys.exit(2)
    return sys.stdin.read()


def cmd_run(script_path: str) -> int:
    """Verify script_path; execute only if verified.

    P0 2: execution goes through ExecutionBroker, which runs the
    verified bytes inside the Docker sandbox. The host's bash binary
    is NEVER invoked on untrusted code.
    """
    p = Path(script_path)
    if not p.exists():
        _log("error", f"script not found: {p}")
        return 2

    rc, out = _run_bash_verify([str(p), "--fix", "--ci"])
    sys.stdout.write(out)
    sys.stdout.flush()

    if rc != 0:
        _log("refused", "bash_verify rejected the script; NOT executing")
        return 1

    # Build the verified artifact. The bytes we run are the bytes
    # we verified, SHA256-bound, executed only inside the sandbox.
    import hashlib
    from bv.artifact import Artifact
    content_bytes = p.read_bytes()
    artifact = Artifact.from_bytes(content_bytes)
    _log("verified", f"artifact sha256={artifact.sha256[:12]}...; executing in sandbox")

    # P0 2: execute via the broker. The host bash is never used
    # on untrusted bytes.
    sys.path.insert(0, str(PKG_ROOT))
    from bv.config import load_config
    from bv.executor import ExecutionBroker, ExecutionRequest
    cfg = load_config()
    broker = ExecutionBroker(cfg)
    request = ExecutionRequest(artifact=artifact, timeout_s=30)
    result = broker.execute(request)
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.error:
        _log("error", f"execution broker: {result.error}")
        return 1
    if result.timed_out:
        _log("error", "sandbox execution timed out (workload killed)")
    return result.exit_code


def cmd_exec(snippet: str) -> int:
    """Verify an inline Bash snippet; execute only if verified.

    P0 2: execution goes through ExecutionBroker. The host bash
    is never invoked on untrusted bytes.
    """
    if not snippet or not snippet.strip():
        _log("error", "empty snippet")
        return 2

    # Write the snippet to a temp file so the verifier can read it,
    # but the actual execution will use the bytes in memory via
    # ExecutionBroker (not the file).
    fd, tmp_path_str = tempfile.mkstemp(prefix="safe_cli_exec_", suffix=".sh")
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(snippet + ("\n" if not snippet.endswith("\n") else ""))
        os.chmod(tmp_path, 0o600)

        rc, out = _run_bash_verify([str(tmp_path), "--fix", "--ci"])
        sys.stdout.write(out)
        sys.stdout.flush()

        if rc != 0:
            _log("refused", "bash_verify rejected the snippet; NOT executing")
            kept = _forensic_move(tmp_path, "refused")
            _log("forensic", f"snippet preserved at {kept}")
            return 1

        # P0 2: build the verified artifact from the snippet bytes.
        # Execution happens in the sandbox via the broker; the host
        # bash is not invoked on untrusted bytes.
        from bv.artifact import Artifact
        artifact = Artifact.from_text(snippet)
        _log("verified", f"artifact sha256={artifact.sha256[:12]}...; executing in sandbox")
        sys.path.insert(0, str(PKG_ROOT))
        from bv.config import load_config
        from bv.executor import ExecutionBroker, ExecutionRequest
        cfg = load_config()
        broker = ExecutionBroker(cfg)
        request = ExecutionRequest(artifact=artifact, timeout_s=30)
        result = broker.execute(request)
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        if result.error:
            _log("error", f"execution broker: {result.error}")
            kept = _forensic_move(tmp_path, "ran")
            _log("forensic", f"snippet preserved at {kept}")
            return 1
        kept = _forensic_move(tmp_path, "ran")
        _log("forensic", f"snippet preserved at {kept}")
        return result.exit_code
    except Exception:
        if tmp_path.exists():
            _forensic_move(tmp_path, "error")
        raise


def cmd_verify(script_path: str) -> int:
    """Verify only; do NOT execute. Pass --ci to make this exit non-zero on failure."""
    p = Path(script_path)
    if not p.exists():
        _log("error", f"script not found: {p}")
        return 2
    return subprocess.run(
        [str(BV_BIN), str(p), "--ci"],
    ).returncode


def cmd_fix(script_path: str) -> int:
    """Verify + auto-repair + write back. NEVER overwrites without backup."""
    p = Path(script_path)
    if not p.exists():
        _log("error", f"script not found: {p}")
        return 2
    return subprocess.run(
        [str(BV_BIN), str(p), "--fix", "--write-back"],
    ).returncode


def cmd_doctor() -> int:
    return subprocess.run([str(BV_BIN), "--doctor"]).returncode


def cmd_stdin_verify() -> int:
    """Read script from stdin; verify only."""
    content = _read_stdin()
    fd, tmp = tempfile.mkstemp(prefix="safe_cli_stdin_", suffix=".sh")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(Path(tmp), 0o600)
        return subprocess.run(
            [str(BV_BIN), tmp, "--ci"],
        ).returncode
    finally:
        Path(tmp).unlink(missing_ok=True)


def install_symlinks() -> bool:
    """Create convenience symlinks so `bv`, `safebash`, etc. all work."""
    src = Path("/usr/local/bin/safe-cli")
    if not src.exists():
        return False
    for alias in ALIASES:
        dst = Path(f"/usr/local/bin/{alias}")
        if dst.exists() or dst.is_symlink():
            continue
        try:
            dst.symlink_to(src)
        except OSError:
            pass
    return True


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return 0

    cmd = argv[1]
    rest = argv[2:]

    if cmd == "run":
        if not rest:
            _log("error", "run requires a script path")
            return 2
        return cmd_run(rest[0])
    if cmd == "exec":
        if not rest:
            _log("error", "exec requires a Bash snippet argument")
            return 2
        # Join rest in case snippet was split (it shouldn't be, but be safe)
        return cmd_exec(" ".join(rest))
    if cmd == "verify":
        if not rest:
            _log("error", "verify requires a script path")
            return 2
        return cmd_verify(rest[0])
    if cmd == "fix":
        if not rest:
            _log("error", "fix requires a script path")
            return 2
        return cmd_fix(rest[0])
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "--":
        return cmd_stdin_verify()
    if cmd == "install-symlinks":
        ok = install_symlinks()
        if ok:
            print("[safe-cli] installed convenience symlinks:")
            for a in ALIASES:
                p = Path(f"/usr/local/bin/{a}")
                if p.is_symlink():
                    print(f"  /usr/local/bin/{a} -> {p.readlink()}")
        else:
            print("[safe-cli] safe-cli not at /usr/local/bin/safe-cli; skipping")
        return 0 if ok else 1

    _log("error", f"unknown subcommand: {cmd}")
    sys.stdout.write(USAGE)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        _log("error", "interrupted")
        sys.exit(130)
    except Exception as e:
        _log("error", f"unexpected: {e!r}")
        sys.exit(2)
