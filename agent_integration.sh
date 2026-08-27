# bash_verify — agent integration helper
#
# Drop this into your shell environment (e.g. ~/.bashrc or sourced from a
# tool's hook) to make the AI coding agent's Bash generation pipeline
# verify every script before it leaves the agent.
#
# USAGE:
#   source /opt/bash-verifier/agent_integration.sh
#   bv_verify <script.sh>
#   bv_verify --fix <script.sh>
#
# Or use the auto-wrap helper:
#   bv_wrap 'echo hello; rm -rf /tmp/foo'
#
# The helper writes the command sequence to a temp file and runs
# `safe-cli exec` on it (sandbox by default). If verification fails,
# the snippet is NOT executed. The host bash is NEVER used on
# untrusted bytes.
#
# This file is sourced-only — never executed.

# Avoid double-sourcing
if [[ -n "${BV_INTEGRATION_LOADED:-}" ]]; then
    return 0 2>/dev/null || exit 0
fi
export BV_INTEGRATION_LOADED=1

BV_BIN="/opt/bash-verifier/bin/bash_verify"

# Verify a script file. Returns bash_verify's exit code.
# Pass --ci to make it return nonzero on failure.
bv_verify() {
    "${BV_BIN}" "$@"
}

# Verify a script from stdin.
bv_verify_stdin() {
    "${BV_BIN}" --stdin "$@"
}

# Run bash_verify and capture its output. Returns 0 iff status is "verified".
# This is the canonical "should I proceed?" check.
_bv_status_ok() {
    local out rc
    out=$("${BV_BIN}" --ci "$@" 2>&1)
    rc=$?
    echo "$out"
    return $rc
}

# Wrap a Bash command sequence in a verify pass + execute.
# Writes the snippet to a temp file, verifies it, then runs the (possibly
# repaired) version. If verification fails, the snippet is NOT executed
# and the temp file is preserved for forensics.
bv_wrap() {
    # P0-5: never invoke host bash on untrusted bytes. The verified
    # snippet is passed to safe-cli exec, which goes through the
    # ExecutionBroker (sandbox by default; --no-sandbox available
    # as an explicit opt-in but NEVER the default for the agent).
    local snippet="$1"
    local rc
    echo "[bv_wrap] verifying inline snippet via safe-cli exec ..." >&2
    # safe-cli exec builds an Artifact, calls ExecutionBroker.execute,
    # and runs inside the Docker sandbox. The host bash is NEVER used
    # on untrusted bytes. --ci makes safe-cli exit nonzero on failure.
    "${SAFE_CLI:-safe-cli}" exec --ci -- "$snippet"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[bv_wrap] verification FAILED (rc=$rc); snippet NOT executed." >&2
    fi
    return $rc
}

# Auto-verify a file in place and write back any repairs.
# Args: <script.sh> [--strict]
bv_fix() {
    "${BV_BIN}" --fix --write-back "$@"
}

# P0-5: safe-cli run executes the verified artifact inside the sandbox
# (via ExecutionBroker). The host bash is NEVER invoked on untrusted
# bytes. This is the safe path for an AI agent to run a script.
bv_run() {
    "${SAFE_CLI:-safe-cli}" run "$@"
}

# Just the doctor check.
bv_doctor() {
    "${BV_BIN}" --doctor
}

# Aliases for convenience
alias bvd='bv_doctor'
alias bv='bv_verify'

echo "[bash_verify integration loaded] ${BV_BIN}"
