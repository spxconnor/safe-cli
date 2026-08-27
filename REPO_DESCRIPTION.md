# safe-cli — Repo Description & README

Below are ready-to-paste assets for a Git repo hosting `safe-cli` / `bash_verify`.

---

## GitHub repo description (short, ~80 chars)

```
One-command Bash safety for AI coding agents — multi-layer verifier + self-healing
```

## GitHub "About" sidebar (longer, ~200 chars)

```
safe-cli verifies and executes Bash through 10 independent analyzers
(tree-sitter, shellcheck, shfmt, bats, docker sandbox, adversarial quoting,
property-based fuzz, side-effect snapshot, self-healing repair). Refuses to
run broken scripts. Designed for AI coding agents that generate Bash.
```

## GitHub topics / keywords

```
bash  shell-verification  static-analysis  ai-coding-agent
shellcheck  tree-sitter  bats  shfmt  docker-sandbox  adversarial-testing
property-based-testing  self-healing  repair-engine  dev-tools  cli
```

---

# safe-cli

> **One-command Bash safety for AI coding agents.**

`safe-cli` verifies and executes Bash through 10 independent analyzers
before any code runs. If verification fails, the script is refused.
Nothing is bypassed. Nothing is deleted.

```
safe-cli run script.sh       # verify then execute
safe-cli exec 'bash snippet' # verify inline Bash then execute
safe-cli verify script.sh    # verify only
safe-cli fix script.sh       # verify + auto-repair + write back
safe-cli doctor              # health check
```

## The 10 verification layers

| # | Layer | What it catches |
|---|---|---|
| 1 | Tree-sitter Bash AST | hard syntax errors, structural problems |
| 2 | bash -n | native Bash syntax errors |
| 3 | ShellCheck | 100+ static rules (quoting, word-splitting, etc.) |
| 4 | shfmt | formatting drift |
| 5 | Bash Language Server | LSP diagnostics |
| 6 | Bats | behavioral / sourcing failures |
| 7 | Docker sandbox | runtime errors, infinite loops (30s timeout) |
| 8 | Adversarial quoting | command injection via 38 hostile inputs |
| 9 | Property-based fuzz | random metacharacter inputs |
| 10 | Side-effect snapshot | unexpected file creation/deletion |

If any layer reports an ERROR-severity diagnostic, `safe-cli` refuses
to execute. The repair engine may auto-fix WARNING-level issues
(minimal diff, intent-preserving). Info-level diagnostics are always
left to the agent/operator.

## Why

AI coding agents generate Bash constantly. Most of it is correct. A
small fraction has bugs that cause data loss or security holes:

- `rm -rf $VAR` instead of `rm -rf "$VAR"` — destroys the wrong path
- `eval "$user_input"` — command injection
- `cd $HOME/important && rm -rf *` — typo + no quoting
- Forgetting `set -e` and silencing errors

`safe-cli` makes those mistakes survivable. It verifies before
executing, refuses broken scripts, and provides a hard-isolated Docker
sandbox for the actual run.

## Install

```bash
# Clone
git clone <repo-url> safe-cli
cd safe-cli

# Install
sudo ./install.sh

# Verify
safe-cli doctor
```

## Usage

```bash
# Verify + execute
safe-cli run ./deploy.sh

# Verify inline Bash then execute
safe-cli exec '
    for f in /tmp/safe/*.txt; do
        echo "Found: $f"
    done
'

# Verify only (CI mode)
safe-cli verify ./script.sh --ci

# Auto-repair
safe-cli fix ./script.sh

# Health check
safe-cli doctor
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Verified (and executed, for `run`/`exec`) |
| 1 | Verification failed — script refused, NOT executed |
| 2 | Argument error / internal error |
| 124 | Timeout (sandbox killed a runaway process) |

## Safety invariants

1. **No `rm`** — `safe-cli` and `install.sh` use `mv` into a `_temp/`
   or timestamped directory; nothing is ever deleted.
2. **No bypass** — if `safe-cli` exits non-zero, the script did not run.
3. **Backups before edits** — the repair engine writes to
   `_temp/backup/<label>-<UTC-timestamp>/` before any in-place edit.
4. **Hard sandbox** — Docker `--read-only`, `--network=none`,
   `--user=nobody`, `--cap-drop=ALL`, 30s timeout, automatic cleanup.
5. **Secrets redacted** — `sk-...`, `AKIA...`, `ghp_...`, PEM blocks,
   bearer tokens, basic-auth URLs are stripped before logging.

## Requirements

- Ubuntu 22.04+ (tested on 22.04 and 24.04)
- Bash 5.x
- Python 3.10+
- Docker (for the runtime sandbox)
- `shellcheck`, `shfmt`, `bats` (installed automatically)
- `tree-sitter` + `tree-sitter-bash` Python bindings
  (installed automatically)

## Project layout

```
safe-cli/
├── bin/
│   ├── safe_cli.py         # main entry point
│   └── bash_verify         # lower-level CLI
├── bv/                     # Python verification package
│   ├── layers/             # 10 analyzer implementations
│   ├── repair/             # self-healing engine
│   ├── sandbox/            # Docker isolation primitives
│   ├── security/           # secret redaction
│   ├── cache/              # static-analysis cache
│   └── reporting/          # JSON / human reports
├── tests/
│   ├── good_scripts/       # reference (passes all 10 layers)
│   ├── broken_scripts/     # safe-pattern failures
│   └── disabled/           # archived dangerous scripts
├── systemd/                # boot-persistence unit files
├── docs/
│   └── ARCHITECTURE.md
├── AGENT_BRIEF.md          # for AI coding agents
├── FUTURE_AGENT_PROMPT.md  # copy-paste template
├── .bashverify.toml        # default config
└── README.md
```

## License

MIT

## Author

Built for production use with AI coding agents. Designed to be safe,
fast, and self-correcting — no single analyzer is trusted; the
verifier refuses rather than guesses.
