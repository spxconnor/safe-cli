# safe-cli

One-command Bash safety for AI coding agents. Verifies before executing, refuses broken scripts.

safe-cli is a small program that runs every Bash script through 10 independent checks before letting it run. If any check finds a problem, the script is refused. Nothing is bypassed. Nothing is deleted.

```
safe-cli run script.sh       # verify then execute
safe-cli exec 'bash snippet' # verify inline Bash then execute
safe-cli verify script.sh    # verify only
safe-cli fix script.sh       # verify + auto-repair + write back
safe-cli doctor              # health check
```

## Why this exists

AI coding agents generate Bash constantly. Most of it is correct. A small fraction has bugs that cause data loss or security holes:

- `rm -rf $VAR` instead of `rm -rf "$VAR"` destroys the wrong path
- `eval "$user_input"` is a command injection
- `cd $HOME/important && rm -rf *` typos and missing quoting
- Forgetting `set -e` and silently swallowing errors

safe-cli makes those mistakes survivable. It verifies before executing, refuses broken scripts, and provides a hard-isolated Docker sandbox for the actual run.

## The 10 verification layers

Each layer is independent. If any one reports a hard error, safe-cli refuses to run the script.

1. Tree-sitter Bash AST. Hard syntax errors, structural problems.
2. bash -n. Native Bash syntax check.
3. ShellCheck. 100+ static analysis rules (quoting, word splitting, etc.).
4. shfmt. Formatting drift detection.
5. Bash Language Server. LSP diagnostics (best effort, 1 second timeout).
6. Bats. Behavioral tests. Auto-generated sourcing and content checks.
7. Docker sandbox. Runtime errors and infinite loops (30 second timeout).
8. Adversarial quoting. 38 hostile inputs that try command injection.
9. Property-based fuzz. Random metacharacter inputs.
10. Side-effect snapshot. Unexpected file creation or deletion in the sandbox.

A self-healing repair engine may apply minimal-diff fixes for WARNING level issues. It will never auto-repair info-level diagnostics or syntax errors. It will never delete functionality to make a test pass.

## Requirements

- Ubuntu 22.04 or newer (also works on Debian, Pop, Linux Mint, elementary, Kali)
- Bash 5.x
- Python 3.10 or newer
- Docker (for the runtime sandbox; layers 7-10 gracefully skip if absent)
- `shellcheck`, `shfmt`, `bats` (installed automatically)
- `tree-sitter` and `tree-sitter-bash` Python bindings (installed automatically)

## Install

The installer is self-healing. It retries each step, falls back to direct binary downloads when apt is unavailable, and runs `--doctor` at the end to verify the system is ready.

```bash
git clone https://github.com/spxconnor/safe-cli.git
cd safe-cli
sudo ./install.sh
```

The installer creates:

- `/usr/local/bin/safe-cli` plus four aliases: `bv`, `safebash`, `safebash-run`, `verify-run`
- `/etc/profile.d/bash_verify.sh` for shell auto-load
- `/opt/bash-verifier/` as the install prefix
- Optional systemd unit and timer (every 15 minutes) if `--with-systemd` is passed

After install, verify the system:

```bash
safe-cli doctor
# Expected: Overall: READY
```

Dry-run mode shows the plan without changing anything:

```bash
./install.sh --dry-run
```

## Usage

Verify a script file:

```bash
safe-cli run /path/to/script.sh
```

If verification fails, safe-cli exits with a non-zero status and does not run the script. The output includes a list of blocking diagnostics with file, line, and column.

Verify inline Bash:

```bash
safe-cli exec '
    for f in /tmp/safe/*.txt; do
        echo "Found: $f"
    done
'
```

The snippet is written to a temp file, verified, and only then executed. If verification fails, the snippet is preserved at `/tmp/safe_cli_exec_*.sh.refused-<timestamp>` for forensics. Nothing is deleted.

Verify only, no execution:

```bash
safe-cli verify /path/to/script.sh
safe-cli verify /path/to/script.sh --ci   # CI mode: nonzero exit on failure
```

Auto-repair:

```bash
safe-cli fix /path/to/script.sh
```

Backups land in `/opt/bash-verifier/_temp/backup/` before any edit.

Health check:

```bash
safe-cli doctor
```

Read from stdin:

```bash
echo 'echo hello' | safe-cli --
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Verified (and executed, for run and exec) |
| 1 | Verification failed. Script refused, not executed. |
| 2 | Argument error or internal error |
| 124 | Timeout. Sandbox killed a runaway process. |

## Interpretation guide

Diagnostics are reported as `[tool/code] file:line:column severity: message`.

| Diagnostic | Severity | Meaning | Action |
|---|---|---|---|
| `[tree_sitter/TS_ERROR]` | error | Hard syntax error in the AST | Rewrite the script |
| `[bash/BASH_SYNTAX]` | error | bash -n reports a syntax error | Rewrite |
| `[shellcheck/SC...]` | warn or info | ShellCheck static rule | Quote variables, use arrays, etc. |
| `[shfmt/SHFMT_DIFF]` | style | Formatting diverges from canonical | Run `shfmt -w` |
| `[bats/BATS_FAIL]` | error | Auto-generated bats test failed | Likely syntax or sourcing issue |
| `[docker_sandbox/-]` exit | error | Sandbox execution failed | Check exit code |
| `[docker_sandbox/-]` timeout | error | Sandbox killed after 30s | Infinite loop |
| `[adversarial/ADVERSARIAL_FAIL]` | error | A function executed injected input | Quote variable expansions |
| `[fuzz/FUZZ_FAIL]` | error | Fuzz input caused crash or unexpected rc | Same as adversarial |
| `[side_effects/UNEXPECTED_*]` | warn | Unexpected file created or deleted in sandbox | Tighten filesystem footprint |

Severity thresholds:

- `error` always blocks verification
- `warning` blocks by default
- `info` never blocks, never auto-repaired
- `style` never blocks, may auto-fix

## Safety invariants

These are enforced by the system and required by the operator.

1. No destructive commands. `rm`, `rm -rf`, `rmdir`, and `find -delete` are forbidden. Use `mv` into a `_temp/` or `disabled/` directory with a timestamp instead.
2. No bypass. If safe-cli exits non-zero, the script did not run.
3. Backups before edits. The repair engine writes to `_temp/backup/<label>-<UTC-timestamp>/` before any in-place edit.
4. Hard sandbox. Docker runs with `--read-only`, `--network=none`, `--user=nobody`, `--cap-drop=ALL`, 30 second timeout, automatic cleanup.
5. Secrets redacted. `sk-...`, `AKIA...`, `ghp_...`, PEM blocks, bearer tokens, and basic-auth URLs are stripped from all logs.

## Project layout

```
safe-cli/
  bin/
    safe_cli.py         # main entry point
    bash_verify         # lower-level CLI
  bv/                   # Python verification package
    layers/             # 10 analyzer implementations
    repair/             # self-healing engine
    sandbox/            # Docker isolation primitives
    security/           # secret redaction
    cache/              # static-analysis cache
    reporting/          # JSON and human report formatters
  tests/
    good_scripts/       # reference (passes all 10 layers)
    broken_scripts/     # safe-pattern failures
    disabled/           # archived dangerous scripts
  systemd/              # boot-persistence unit files
  docs/ARCHITECTURE.md  # architectural reference
  AGENT_BRIEF.md        # for AI coding agents
  FUTURE_AGENT_PROMPT.md # copy-paste template
  .bashverify.toml      # default config
  install.sh            # self-healing installer
  install_persistence.sh # systemd or PM2 install
  agent_integration.sh  # shell helpers (auto-loaded)
  LICENSE
  README.md
```

## For AI coding agents

If you are an AI agent operating on a server where safe-cli is installed:

1. Use `safe-cli` for all Bash work. It is on PATH at `/usr/local/bin/safe-cli`.
2. Read `/opt/bash-verifier/AGENT_BRIEF.md` (or `/opt/bash-verifier/CLAUDE.md`, `/opt/bash-verifier/AGENTS.md`, `/root/CLAUDE.md`) at the start of any session that involves Bash on this server.
3. Wrap every non-trivial Bash command in safe-cli.
4. Never use `rm`. Use `mv` into a `_temp/` directory instead.
5. Never execute a script safe-cli refused.
6. Always back up before modifying: `cp file _temp/file.before-edit.bak`.

## License

MIT
