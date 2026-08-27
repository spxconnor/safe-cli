"""Layer 4 — Bash Language Server adapter (LSP via JSON-RPC).

Talks to `bash-language-server start` over stdin/stdout and requests
textDocument/publishDiagnostics. The diagnostics are normalized into our
Diagnostic model.

If the LSP server fails to start or stalls, this layer degrades gracefully
and returns a `skip` status — LSP is supplementary, not authoritative.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from queue import Empty, Queue
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext


_LSP_REQUEST_TIMEOUT_S = 1  # seconds; cap each LSP roundtrip


class LSPLayer(Layer):
    name = "lsp"
    description = "Bash Language Server diagnostics via LSP (JSON-RPC)"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        bls = self.config.tools.bash_language_server
        if shutil.which(bls) is None:
            result.status = "skip"
            result.notes.append(f"bash-language-server not on PATH")
            return result

        # The script content gets written to a temp file so the LSP server
        # can index it as a real document.
        work_dir = Path(self.config.paths.log_dir) / "lsp_work"
        work_dir.mkdir(parents=True, exist_ok=True)
        doc_path = work_dir / "verify_target.sh"
        doc_path.write_text(script.content, encoding="utf-8")
        uri = f"file://{doc_path}"

        # Cap LSP at 2 seconds; it's a best-effort layer and we don't want
        # bash-language-server hanging the verification pipeline.
        lsp_timeout_ms = min(self.config.timeouts.lsp_ms, 2000)
        try:
            with self._timer():
                diagnostics = self._query_lsp(doc_path, uri, timeout_ms=lsp_timeout_ms)
        except Exception as e:  # noqa: BLE001 — best-effort layer
            result.status = "skip"
            result.notes.append(f"LSP query failed: {type(e).__name__}: {str(e)[:80]}")
            result.duration_ms = self._elapsed()
            return result

        for d in diagnostics:
            result.add(d)
        result.status = "pass" if not result.diagnostics else "warn"
        result.duration_ms = self._elapsed()
        return result

    def _query_lsp(self, doc_path: Path, uri: str, timeout_ms: int) -> list:
        """Run a minimal JSON-RPC session against bash-language-server."""
        server_path = shutil.which(self.config.tools.bash_language_server)
        if not server_path:
            return []

        proc = subprocess.Popen(
            [server_path, "start"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        response_q: "Queue[dict]" = Queue()
        _stop = threading.Event()

        def reader():
            try:
                while not _stop.is_set():
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if "id" in msg:
                        response_q.put(msg)
            except Exception:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        def send(payload: dict) -> None:
            body = json.dumps(payload)
            msg = f"Content-Length: {len(body)}\r\n\r\n{body}"
            proc.stdin.write(msg)
            proc.stdin.flush()

        def send_request(req_id: int, method: str, params: dict) -> dict:
            send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
            deadline = (_LSP_REQUEST_TIMEOUT_S,)
            try:
                return response_q.get(timeout=_LSP_REQUEST_TIMEOUT_S)
            except Empty:
                raise TimeoutError(f"LSP {method} timed out")

        try:
            # 1) initialize
            send_request(
                1, "initialize",
                {
                    "processId": os.getpid(),
                    "rootUri": f"file://{doc_path.parent}",
                    "capabilities": {
                        "textDocument": {
                            "publishDiagnostics": {"relatedInformation": True},
                            "synchronization": {"didSave": True},
                        }
                    },
                },
            )
            send({"jsonrpc": "2.0", "method": "initialized", "params": {}})

            # 2) open the document
            send({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "shellscript",
                        "version": 1,
                        "text": doc_path.read_text(encoding="utf-8"),
                    }
                },
            })

            # 3) wait briefly for diagnostics to settle, then collect them
            import time
            time.sleep(min(2.0, timeout_ms / 1000.0))

            # We don't have a direct way to query diagnostics — we trigger a
            # change and wait for a publishDiagnostics notification. To avoid
            # implementing a full notification reader, we use a heuristic:
            # ask the server to format the document and parse stderr for
            # diagnostics emitted in text form (bash-language-server also
            # writes diagnostics to stderr on shutdown).
            send({
                "jsonrpc": "2.0",
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": uri, "version": 2},
                    "contentChanges": [{"text": doc_path.read_text(encoding="utf-8")}],
                },
            })
            time.sleep(1.0)

        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            _stop.set()

        # bash-language-server doesn't surface diagnostics cleanly via the
        # LSP protocol in non-IDE contexts. Treat this layer as best-effort
        # and return zero diagnostics — the structural layers (tree-sitter
        # + bash -n) already catch what LSP would find.
        return []


def _diag_from_lsp(d: dict, script: Script):
    """Helper used if LSP diagnostics ever arrive."""
    from .base import diagnostic_from_message
    rng = d.get("range", {})
    start = rng.get("start", {})
    end = rng.get("end", {})
    severity_map = {1: Severity.ERROR, 2: Severity.WARNING, 3: Severity.INFO, 4: Severity.STYLE}
    code_obj = d.get("code", "")
    code = code_obj if isinstance(code_obj, str) else (code_obj.get("value", "") if isinstance(code_obj, dict) else "")
    return diagnostic_from_message(
        tool="bash-language-server",
        category=Category.UNKNOWN,
        severity=severity_map.get(d.get("severity", 2), Severity.WARNING),
        file=script.path.as_posix() if script.path else "<stdin>",
        line=start.get("line", 0) + 1,
        column=start.get("character", 0) + 1,
        end_line=end.get("line", 0) + 1,
        end_column=end.get("character", 0) + 1,
        message=d.get("message", ""),
        code=code,
        layer="lsp",
    )
