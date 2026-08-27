# AGENT BRIEF — bash_verify + safe-cli (Multi-Layer Bash Safety)

> **You are an AI coding agent.** Before generating, modifying, or executing
> any Bash script on this server, **read this brief end-to-end**.
> Use `safe-cli`. It is your safety net.
>
> **This server runs `bash_verify` 24/7 and will block broken scripts
> from executing.** Workflow integration is automatic.

---

## ⭐ ONE COMMAND — safe-cli

Every AI agent should use **`safe-cli`** for all Bash work. It is on
`PATH` and works from any cwd, in any shell, in any tool.

```bash
safe-cli doctor                       # health check (must be READY)
safe-cli run /path/to/script.sh       # verify then execute; refuses if broken
safe-cli exec 'echo Hello, $USER'     # inline verify then execute
safe-cli verify /path/to/script.sh    # verify only, no execution
safe-cli fix /path/to/script.sh       # verify + auto-repair + write back
safe-cli help                         # full help
```

**If `safe-cli` exits non-zero, do NOT execute the script.** Repair it
first or ask the operator.

Aliases (all equivalent):
```bash
bv               # short form, recommended for one-liners
safebash         # explicit form
safebash-run     # explicit form
verify-run       # explicit form
```

All four resolve to the same `/usr/local/bin/safe-cli`.

---

## TL;DR (60-second briefing)

1. **Every Bash command you generate should be verified.**
   - Single-line harmless shell commands: just execute them.
   - Multi-line scripts or anything non-trivial: **`safe-cli run`**
     or **`safe-cli exec`** them first.
2. **`safe-cli` is the single command.** It wraps everything.
3. **If safe-cli exits non-zero, do NOT execute.** Repair and re-verify.
4. **No destructive commands.** Never `rm`. Use `mv` into `_temp/` or
   `disabled/`.

---

## What bash_verify + safe-cli do

A production-grade, defense-in-depth verification system for Bash scripts.
10 independent analyzers cross-check each other; nothing is trusted alone.

```
                AI CODING AGENT  (you)
                       │
                       ▼  safe-cli run script.sh
                       │
            /usr/local/bin/safe-cli
                       │
                       ▼
            /opt/bash-verifier/bin/bash_verify
                       │
   ┌──────────────────────────────────────────────┐
   │  1. Tree-sitter Bash AST  → parse + structure│
   │  2. bash -n               → native syntax   │
   │  3. ShellCheck            → 100+ static rules│
   │  4. shfmt                 → formatting diff │
   │  5. Bash Language Server  → LSP diagnostics │
   │  6. Bats                  → behavioral tests│
   │  7. Docker sandbox        → hard-isolated run│
   │  8. Adversarial quoting   → 38 hostile inputs│
   │  9. Property-based fuzz   → random metachar │
   │ 10. Side-effect snapshot  → unexpected files│
   └──────────────────────────────────────────────┘
                       │
                       ▼
                Self-Healing Repair Engine
                       │
                       ▼
                VERIFIED  or  FAILED  → refuse + preserve forensic copy
```

---

## How to use safe-cli

### 1. Verify + execute a script

```bash
safe-cli run /path/to/script.sh
```

If verification fails, safe-cli exits 1 and **does not run the script**.

### 2. Verify + execute inline Bash

```bash
safe-cli exec '
    for f in /tmp/bv_safe_demo/*.txt; do
        echo "$f"
    done
'
```

The snippet is written to a temp file, verified, and only then executed.
If verification fails, the snippet is preserved at
`/tmp/safe_cli_exec_*.sh.refused-<timestamp>` for forensics.

### 3. Verify only (no execution)

```bash
safe-cli verify /path/to/script.sh
```

Exit 0 = verified; non-zero = failed. Use this in CI / pre-commit.

### 4. Auto-repair

```bash
safe-cli fix /path/to/script.sh
```

Verifies, applies minimal-diff repairs, and writes back to the original
file. Backups land in `/opt/bash-verifier/_temp/backup/`.

### 5. Doctor / health check

```bash
safe-cli doctor
# Expected output: 13/13 components PASS, Overall: READY
```

### 6. Read from stdin

```bash
echo 'echo hello' | safe-cli --
```

---

## Interpretation guide — what each diagnostic means

| Diagnostic code | Severity | Meaning | Action |
|---|---|---|---|
| `[tree_sitter/TS_ERROR]` | error | Hard syntax error in the AST | Rewrite the script |
| `[bash/BASH_SYNTAX]` | error | bash -n reports a syntax error | Rewrite |
| `[shellcheck/SC*]` | warn/info | ShellCheck static rule | Quote variables, use arrays, etc. |
| `[shfmt/SHFMT_DIFF]` | style | Formatting diverges from canonical | Run `shfmt -w` |
| `[bats/BATS_FAIL]` | error | Auto-generated bats test failed | Likely syntax or sourcing issue |
| `[docker_sandbox/-]` exit | error | Sandbox execution failed | Check exit code |
| `[docker_sandbox/-]` timeout | error | Sandbox killed after 30s | Infinite loop |
| `[adversarial/ADVERSARIAL_FAIL]` | error | Function executed injected input | Quote variable expansions |
| `[fuzz/FUZZ_FAIL]` | error | Fuzz input caused crash | Same as adversarial |
| `[side_effects/UNEXPECTED_*]` | warn | Unexpected file created/deleted | Tighten filesystem footprint |

### Severity thresholds

- `error` → always blocks verification
- `warning` → blocks by default
- `info` → never blocks; never auto-repaired
- `style` → never blocks; may auto-fix

---

## Safety rules — non-negotiable

These are enforced by the system and by the operator's standing orders.

### 1. NEVER use destructive commands

```bash
# FORBIDDEN:
rm file
rm -rf /some/path
rmdir some_dir
find ... -delete

# REQUIRED:
mv file _temp/file.disabled-$(date +%s)
mv some_dir _temp/some_dir.disabled-$(date +%s)
```

The reasoning: every "destructive" command could destroy real user data
if mistyped. The convention is to move files aside with timestamps.
The agent can always move them back, but a deleted file is gone forever.

### 2. NEVER execute a script that safe-cli rejected

```bash
# BAD:
safe-cli run /path/to/script.sh       # exits non-zero
bash /path/to/script.sh               # <-- do NOT do this

# GOOD:
safe-cli run /path/to/script.sh       # exits 0 only if verified
```

`safe-cli run` and `safe-cli exec` enforce this automatically.

### 3. ALWAYS back up before modifying

`safe-cli fix` does this automatically. For your own edits:

```bash
cp script.sh _temp/script.sh.before-edit-$(date +%s).bak
# ...edit script.sh...
```

### 4. Use the Docker sandbox for untrusted Bash

The sandbox (always enabled by default) provides:
- Read-only root filesystem
- No network (configurable)
- User `nobody` (no privilege escalation)
- `--cap-drop=ALL`
- Strict timeout (30s)
- Automatic cleanup

### 5. Respect the `disabled/` directory

Some broken scripts are archived in
`/opt/bash-verifier/tests/disabled/*.sh.disabled` — they are
deliberately NOT executed. To recover:

```bash
mv tests/disabled/script.sh.disabled tests/broken_scripts/script.sh
# now run it (carefully)
```

---

## Where things live

```
/opt/bash-verifier/                      ← root of the system
├── bin/
│   ├── bash_verify                      ← CLI entry (self-bootstrapping)
│   └── safe_cli.py                      ← safe-cli entry (copy at /usr/local/bin/safe-cli)
├── bv/                                  ← Python package
├── tests/
│   ├── good_scripts/                    ← reference (passes all 10 layers)
│   ├── broken_scripts/                  ← safe-pattern failures
│   ├── disabled/                        ← archived dangerous scripts (NEVER run)
│   ├── adversarial_corpus/              ← regression for adversarial layer
│   └── fuzz_corpus/                     ← crash corpus from fuzzing
├── systemd/                             ← boot-persistence unit files
├── ecosystem.bash-verify.config.js       ← PM2 config (alternative)
├── install_persistence.sh               ← systemd or PM2 installer
├── agent_integration.sh                 ← shell helpers (sourced via /etc/profile.d)
├── .bashverify.toml                     ← default config
├── README.md                            ← operator manual
├── docs/ARCHITECTURE.md                 ← architectural reference
├── AGENT_BRIEF.md                       ← THIS FILE
└── _temp/
    ├── cache/                           ← static-analysis cache
    ├── backup/                          ← per-repair backups (NEVER rm)
    └── logs/                            ← LSP work dirs + repair logs

/usr/local/bin/
├── safe-cli                             ← PRIMARY ENTRY POINT for AI agents
├── bv -> safe-cli                       ← alias
├── safebash -> safe-cli                 ← alias
├── safebash-run -> safe-cli             ← alias
└── verify-run -> safe-cli               ← alias

/etc/profile.d/bash_verify.sh            ← auto-sources shell helpers into every shell
/etc/systemd/system/bash-verify-doctor.{service,timer}  ← boot-persistent health check
```

---

## Common failure modes and what to do

### "ModuleNotFoundError: No module named 'bv'"

Run `safe-cli doctor`. If that also fails:

```bash
ls /opt/bash-verifier/bv/__init__.py
safe-cli doctor
```

If `safe-cli` is at the wrong location, reinstall:

```bash
cp /opt/bash-verifier/bin/safe_cli.py /usr/local/bin/safe-cli
chmod +x /usr/local/bin/safe-cli
safe-cli install-symlinks
```

### "Incompatible Language version 15. Must be between 13 and 14"

The tree-sitter binding is mismatched. Re-pin:

```bash
pip3 install --quiet "tree-sitter==0.21.3" "tree-sitter-bash==0.21.0"
```

### "Docker daemon unavailable"

Sandbox layers will skip if Docker is down. Restart:

```bash
systemctl status docker
systemctl restart docker
```

### "bash-language-server times out"

Expected behavior; the layer gracefully skips after 1 second.

---

## Self-testing the system

When you modify bash_verify itself, you must re-run:

```bash
safe-cli doctor
safe-cli run /opt/bash-verifier/tests/good_scripts/hello_world.sh
safe-cli verify /opt/bash-verifier/tests/broken_scripts/03_bad_syntax.sh ; echo "rc=$?"
safe-cli verify /opt/bash-verifier/tests/broken_scripts/10_infinite_loop.sh ; echo "rc=$?"
```

If any of these regress, your change broke something. Fix before
committing.

---

## Persistence and audit

- systemd timer `bash-verify-doctor.timer` runs `--doctor` every 15 min
- journald logs: `journalctl -u bash-verify-doctor.service -n 50`
- Repair backups live under `/opt/bash-verifier/_temp/backup/`
- Forensic files from `safe-cli exec` live under `/tmp/safe_cli_exec_*.sh.<suffix>-<timestamp>`

To install or reinstall persistence:

```bash
/opt/bash-verifier/install_persistence.sh systemd    # preferred
/opt/bash-verifier/install_persistence.sh pm2        # alternative
```

---

## Versioning and pinning

When upgrading tree-sitter bindings:

```bash
pip3 install --quiet "tree-sitter==<ver>" "tree-sitter-bash==<matching-ver>"
```

When upgrading shellcheck/shfmt/bats, re-run the broken corpus.

When upgrading the sandbox image:

```bash
docker pull bash:5.1
```

---

## The standing rule (every agent session)

1. **`safe-cli` for all Bash.** Verify before executing.
2. **No destructive commands.** `mv` to `_temp/` or `disabled/` instead.
3. **Back up before modifying.** `cp` to `_temp/backup/` first.
4. **If unsure, ask the operator.** The system is here to protect you;
   don't bypass it.

Welcome. Be safe. Be precise.
