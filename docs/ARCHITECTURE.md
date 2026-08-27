# bash_verify — Architecture

## Goal

Make AI-generated Bash scripts as reliable as practically possible by
verifying them through **multiple independent analyzers** that cross-check
each other, then optionally **repair** failures via minimal, intent-
preserving edits.

No single analyzer is trusted. The system refuses to claim "verified"
unless every applicable gate passes.

## Pipeline Order

```
1. tree_sitter     (parse + structure)
       ↓
2. bash_n          (native syntax)
       ↓ early-exit if hard syntax error
3. shellcheck      (static analysis)
       ↓
4. shfmt           (formatting diff)
       ↓
5. lsp             (LSP diagnostics — best effort)
       ↓
6. bats            (behavioral)
       ↓
7. sandbox         (Docker-isolated execution)
       ↓
8. adversarial     (hostile input corpus)
       ↓
9. fuzz            (random inputs)
       ↓
10. side_effects   (snapshot diff)
       ↓
11. repair_engine  (only if blocking diagnostics exist)
       ↓
12. report         (JSON + human)
```

## Layer Interface

Every layer implements `Layer.run(script, context) -> LayerResult`.

```python
class Layer(abc.ABC):
    name: str
    description: str
    def run(self, script: Script, context: LayerContext) -> LayerResult: ...
```

`LayerResult` carries diagnostics, notes, metadata, and timing.
Diagnostics are normalized so the repair engine can reason about them
uniformly.

## Diagnostic Model

```python
@dataclass
class Diagnostic:
    tool: str               # "shellcheck"
    category: Category      # QUOTING | SECURITY | RUNTIME | ...
    severity: Severity      # error | warning | info | style
    file: str
    line: int               # 1-based
    column: int
    end_line: int
    end_column: int
    message: str
    code: str               # e.g. "SC2086"
    confidence: float
    repairable: bool
    suggested_action: str
    raw_output: str
    layer: str
    fingerprint: str        # stable hash for caching & dedup
```

## Repair Engine

```text
generate   →   verify   →   collect diagnostics
                                   ↓
                         prioritize (security → syntax → runtime → ...)
                                   ↓
                         find strategy
                                   ↓
                         apply minimal diff
                                   ↓
                         backup first (NEVER overwrite without backup)
                                   ↓
                         re-verify
                                   ↓
                       (loop until pass or limit)
```

Limits:

- `max_repair_attempts` (default 3)
- `max_identical_diagnostics` (default 4)
- `max_total_seconds` (default 180)

When any limit is hit, the engine returns `RepairReport.aborted_reason`.

## Sandbox Isolation

The Docker sandbox is the **only** execution path that should run
untrusted Bash:

- Read-only root filesystem
- `network=none` by default
- `user=nobody` (65534)
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- tmpfs at `/tmp` and `/work`
- Memory + CPU + pids limits
- Strict timeout (default 30s)
- Auto-destroy on exit

`/etc/hosts`, `/etc/resolv.conf`, SSH keys, and `~/.bash_history` are
never visible to the sandboxed script.

## Cache Strategy

Only **static-analysis** layers are cached (tree_sitter, bash_n,
shellcheck, shfmt, lsp). Cache key is a hash of:
- script content
- layer name
- relevant config knobs

Cached results expire after `cache.ttl_seconds` (default 1h).

Runtime layers (bats, sandbox, adversarial, fuzz, side_effects) are
**never** cached — they depend on the live environment.

## Reporting

Two outputs:

- **Human**: terminal-friendly summary
- **JSON**: full structured report for CI / dashboards

Both redact known secret patterns (sk-..., ghp_..., AKIA..., PEM blocks,
bearer tokens, basic-auth in URLs) before logging.

## Adding a New Layer

1. Create `bv/layers/<name>_layer.py`
2. Subclass `Layer`, implement `run()`
3. Register in `bv/orchestrator.py` `Orchestrator.__init__`
4. Add the layer name to `LAYER_ORDER`
5. Add a smoke test in `tests/broken_scripts/`
6. Update `README.md` status table

## Adding a New Repair Strategy

1. Add a function in `bv/repair/strategies.py`
2. Register it in `STRATEGIES` list
3. Test on a broken script via `bash_verify --fix script.sh`
4. Confirm the diff vs the backup is minimal

## Known Limitations

- **Bash Language Server** does not surface diagnostics over the LSP
  protocol in non-IDE contexts. The layer gracefully skips.
- **Fuzz** uses Python's stdlib `random` — not cryptographic randomness.
  For crash reproducibility, `context.extra["fuzz_seed"]` is honored.
- **Side-effect detection** is filesystem-only. It does not monitor
  network or process creation from inside the sandbox; if those matter,
  add an explicit layer (e.g. `pcap`-based or `strace`-based).
- **Self-healing** does not handle syntax errors — those are never
  safe to auto-repair. The engine refuses and reports.

## Safety Invariants (DO NOT BREAK)

1. `bash_verify` MUST NOT use `rm` on user files or backups.
2. `bash_verify` MUST NOT modify a script in place without first
   writing a backup to `_temp/backup/`.
3. The Docker sandbox MUST run with `--read-only`, `network=none`,
   and `cap-drop=ALL` by default.
4. Repair strategies MUST be minimal-diff and MUST preserve original
   intent.
5. Diagnostic output MUST redact known secret patterns before logging.
6. The verifier MUST return `FAILED` rather than auto-repair when the
   only available fix is destructive.
