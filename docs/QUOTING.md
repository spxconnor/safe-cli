# Conservative Bash Quoting Intelligence & Self-Healing Engine

This document describes the `bv/quoting/` subsystem in safe-cli.

**It is NOT** mathematically perfect Bash semantics.

**It is** conservative, semantics-aware, source-span-based, evidence-based,
sandbox-validated, and regression-tested.

## What it does

The quoting subsystem scans Bash source for risky unquoted expansions and
proposes minimal source-span edits to fix them. It is intentionally
designed to *refuse* to touch:

- `$@`, `$*`, `${arr[@]}`, `${arr[*]}` — array/positional semantics
- `eval`, `exec`, `source` — dynamic execution sinks
- Heredoc bodies — protected lexical regions
- `[ ]` vs `[[ ]]` — different expansion semantics
- Assignments (`VAR=...`) — different splitting rules

## What it does NOT do

- It does **not** blindly quote every variable.
- It does **not** perform global regex source rewrites.
- It does **not** delete code, comment out code, or change control flow.
- It does **not** claim universal Bash semantic equivalence.

## CLI

```bash
safe-cli-quote quote-check <file>
safe-cli-quote quote-explain <file>
safe-cli-quote quote-fix <file> [--apply] [--backup PATH]
safe-cli-quote quote-doctor
```

`--format json` is supported on all subcommands.

## Stable rule IDs

| ID             | Meaning                                                   |
| -------------- | --------------------------------------------------------- |
| BV-QUOTE-001   | Unquoted scalar parameter expansion (word splitting)      |
| BV-QUOTE-002   | Unquoted command substitution (word splitting)            |
| BV-QUOTE-003   | Unquoted arithmetic expansion                             |
| BV-QUOTE-004   | Unquoted path expansion may undergo pathname expansion    |
| BV-QUOTE-005   | Unquoted expansion may disappear when empty/unset         |
| BV-QUOTE-006   | Dynamic shell evaluation (`eval`/`exec`/`source`)         |
| BV-QUOTE-007   | Possible intentional list expansion                       |
| BV-QUOTE-008   | Array expansion requires semantic review                  |
| BV-QUOTE-009   | `$@` / `$*` semantic ambiguity                            |
| BV-QUOTE-010   | Quote removal may change argument boundaries              |
| BV-QUOTE-011   | Mixed quoted and unquoted expansion                       |
| BV-QUOTE-012   | Unsafe nested expansion                                   |
| BV-QUOTE-013   | Potentially unsafe word splitting                         |
| BV-QUOTE-014   | Potentially unsafe glob expansion                         |
| BV-QUOTE-015   | Ambiguous quoting intent                                  |
| BV-QUOTE-016   | Repair would change argument cardinality                  |
| BV-QUOTE-017   | Repair would change empty-variable behavior               |
| BV-QUOTE-018   | Repair changes shell argument semantics                   |

## Hard no-go conditions (spec section 24)

A candidate is NEVER auto-applied if it would:

- change the command name
- change control flow or pipeline structure
- change redirection target semantics
- change `$@` / `$*` semantics
- change array semantics
- change an intentionally expanded heredoc
- introduce or remove `eval`
- delete or comment out code
- change a function signature
- exceed the byte-budget from `[repair]`

## Repair budgets

Default:

```python
RepairBudget(
    max_edits=3,
    max_changed_bytes=128,
    require_reverify=True,
    require_behavioral_validation=True,
)
```

Plus a confidence gate:

```
confidence >= 0.95
semantic_risk == "low"
severity in {"info", "warning"}    # never auto-fix "error" rules
```

## Atomic commit (spec section 41)

When a candidate is auto-accepted, the writing path:

1. Writes the original source to the configured backup path (if any).
2. Writes the patched bytes to a temp file in the same directory.
3. `flush()` + `fsync()` the temp file.
4. `os.replace()` to the final path.

This guarantees that either the old file is intact or the new file is
fully written. There is no partial-write state.

## Validation chain (spec section 27)

For every accepted candidate:

1. Hash the patched bytes.
2. Run `bash -n` via stdin (does NOT execute, only parses).
3. Re-run the analyzer on the patched bytes.
4. Run ShellCheck if available.
5. Optional: differential execution via `bv.executor.ExecutionBroker`.

The host never invokes `bash` with `-c` on user bytes.

## Integration with the existing pipeline

The quoting subsystem:

- Does NOT bypass `bv.artifact.Artifact`.
- Does NOT bypass `bv.executor.ExecutionBroker`.
- Does NOT bypass the existing `bv.heredoc/` parser.
- Uses the existing redaction logic in `bv/security/redaction.py`.
- Emits audit events via `bv/audit/` when applied.

## Tests

`tests/quoting/` contains 76 tests covering:

- All 11 mandatory regression fixtures from spec section 68.
- Catastrophic-repair prevention (spec section 82).
- No destructive repair (spec section 83).
- Source preservation (spec section 84).
- Idempotence and oscillation (spec sections 85, 62).
- Renderer contracts (text + JSON).
- Validator contracts.
- Performance sanity (10,000-line script).
- No host execution during analysis.

## Known limitations

- The intent classifier uses a small allowlist of variable-name hints.
  Unusual names fall back to `UNKNOWN`, which is the right default.
- The tokenizer does not handle every Bash edge case. When in doubt it
  returns nothing rather than producing a wrong finding.
- Differential sandbox validation requires the `bv.executor` module and
  Docker, so it is OFF by default in `quote-check`.
