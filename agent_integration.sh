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
# `bash_verify --fix --write-back` on it. If verification fails (status
# != "verified"), the snippet is NOT executed. The temp file is moved
# aside for forensics instead of being deleted.
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
    local snippet="$1"
    local tmp out rc
    tmp=$(mktemp -t bv_wrap_XXXXXX.sh)
    printf '%s\n' "$snippet" > "$tmp"
    echo "[bv_wrap] verifying $tmp ..." >&2
    # --ci makes bash_verify exit nonzero on failure.
    out=$("${BV_BIN}" "$tmp" --fix --ci 2>&1)
    rc=$?
    echo "$out"
    if [[ $rc -ne 0 ]]; then
        echo "[bv_wrap] verification FAILED (rc=$rc); snippet NOT executed." >&2
        mv "$tmp" "${tmp}.failed-$(date +%s)"
        return $rc
    fi
    echo "[bv_wrap] verified; executing $tmp ..." >&2
    bash "$tmp"
    rc=$?
    mv "$tmp" "${tmp}.ran-$(date +%s)"
    return $rc
}

# Auto-verify a file in place and write back any repairs.
# Args: <script.sh> [--strict]
bv_fix() {
    "${BV_BIN}" --fix --write-back "$@"
}

# Just the doctor check.
bv_doctor() {
    "${BV_BIN}" --doctor
}

# Aliases for convenience
alias bvd='bv_doctor'
alias bv='bv_verify'

echo "[bash_verify integration loaded] ${BV_BIN}"
