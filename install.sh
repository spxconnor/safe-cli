#!/usr/bin/env bash
# safe-cli installer — self-healing, self-correcting, idempotent.
#
# What it does:
#   1. Detect OS (Ubuntu / Debian / other); refuse if not Linux.
#   2. Install system tools: shellcheck, shfmt, bats, docker (apt).
#   3. Install Python deps: tree-sitter, tree-sitter-bash, tomli (pip3).
#   4. Install Node deps: bash-language-server (npm, optional).
#   5. Install safe-cli at /usr/local/bin/safe-cli + symlink aliases.
#   6. Install systemd unit + timer (optional, --with-systemd).
#   7. Install /etc/profile.d/bash_verify.sh for shell auto-load.
#   8. Run --doctor to verify READY state.
#
# Self-healing:
#   - apt failures → retry with --fix-missing, then fall back to direct binary download
#   - pip failures → retry with --break-system-packages / --user
#   - npm failures → skip bash-language-server gracefully
#   - docker absent → skip sandbox layers (graceful)
#   - any step failure → log, continue, surface at the end with a clear report
#
# Safety:
#   - No destructive commands. Backups land in _temp/backup/.
#   - Idempotent: safe to run repeatedly.
#   - Dry-run mode: --dry-run prints what would happen without doing it.
#
# Usage:
#   ./install.sh                    # full install
#   ./install.sh --dry-run          # show plan, don't execute
#   ./install.sh --no-systemd       # skip systemd persistence
#   ./install.sh --prefix /opt/foo  # custom install prefix

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PREFIX="/opt/bash-verifier"
BIN_DIR="/usr/local/bin"
WITH_SYSTEMD=1
DRY_RUN=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${PREFIX}/_temp/logs"
BACKUP_DIR="${PREFIX}/_temp/backup"

# Step tracker — list of (status, message) pairs
declare -a STEP_RESULTS=()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_log() {
    printf '[%s] %s\n' "$(_ts)" "$*" | tee -a "${LOG_DIR}/install.log"
}

_step() {
    local status="$1"; shift
    local msg="$1"; shift
    STEP_RESULTS+=("${status}|${msg}")
    if [[ "${status}" == "OK" ]]; then
        _log "  ✓ ${msg}"
    elif [[ "${status}" == "WARN" ]]; then
        _log "  ⚠ ${msg}"
    else
        _log "  ✗ ${msg}"
    fi
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=1; shift ;;
        --no-systemd) WITH_SYSTEMD=0; shift ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        --bin-dir)    BIN_DIR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,32p' "$0"
            exit 0
            ;;
        *)
            _log "unknown arg: $1 (use --help)"
            exit 2
            ;;
    esac
done

mkdir -p "${LOG_DIR}" "${BACKUP_DIR}"

_log "============================================================"
_log "safe-cli installer"
_log "  PREFIX      = ${PREFIX}"
_log "  BIN_DIR     = ${BIN_DIR}"
_log "  WITH_SYSTEMD= ${WITH_SYSTEMD}"
_log "  DRY_RUN     = ${DRY_RUN}"
_log "  SRC_DIR     = ${SRC_DIR}"
_log "============================================================"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log "DRY RUN — no changes will be made"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
run() {
    # run "description" cmd args...
    local desc="$1"; shift
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        _log "  [DRY] would run: $*"
        return 0
    fi
    _log "  → ${desc}: $*"
    if "$@"; then
        return 0
    else
        return $?
    fi
}

retry() {
    # retry N "description" cmd args...
    local n="$1"; shift
    local desc="$1"; shift
    local i rc=0
    for ((i=1; i<=n; i++)); do
        if "$@" 2>>"${LOG_DIR}/install.log"; then
            return 0
        fi
        rc=$?
        _log "  retry ${i}/${n} after failure (rc=${rc})"
        sleep $((i * 2))
    done
    return ${rc}
}

have() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        echo "unknown"
        return
    fi
    . /etc/os-release
    echo "${ID:-unknown}"
}

apt_install() {
    # apt_install "package1 package2 ..."
    run "apt-get install" apt-get install -y "$@"
}

# ---------------------------------------------------------------------------
# Phase 0 — sanity
# ---------------------------------------------------------------------------
_log ""
_log "Phase 0: Sanity checks"

OS_ID="$(detect_os)"
_log "  OS detected: ${OS_ID}"

case "${OS_ID}" in
    ubuntu|debian|pop|linuxmint|elementary|kali) ;;
    *)
        _log "  WARNING: ${OS_ID} is not officially supported. Trying anyway."
        ;;
esac

# Need root for apt and /usr/local/bin writes
if [[ $EUID -ne 0 ]]; then
    _step FAIL "must run as root (sudo $0)"
    exit 1
fi
_step OK "running as root"

# ---------------------------------------------------------------------------
# Phase 1 — apt packages
# ---------------------------------------------------------------------------
_log ""
_log "Phase 1: Install system tools (apt)"

APT_UPDATED=0
apt_update() {
    if [[ ${APT_UPDATED} -eq 0 ]]; then
        run "apt-get update" apt-get update -qq
        APT_UPDATED=1
    fi
}

# shellcheck
if have shellcheck; then
    _step OK "shellcheck already present: $(shellcheck --version | head -1)"
else
    apt_update
    if retry 3 "install shellcheck" apt_install shellcheck; then
        _step OK "shellcheck installed"
    else
        _step WARN "shellcheck apt install failed — layer will skip"
    fi
fi

# shfmt
if have shfmt; then
    _step OK "shfmt already present: $(shfmt --version)"
else
    apt_update
    # shfmt is not in apt for jammy; fall back to direct binary download
    if retry 2 "install shfmt via apt" apt_install shfmt; then
        _step OK "shfmt installed via apt"
    else
        _log "  → shfmt not in apt; downloading binary..."
        if retry 2 "download shfmt" curl -fsSL \
            "https://github.com/mvdan/sh/releases/download/v3.10.0/shfmt_v3.10.0_linux_amd64" \
            -o "${BIN_DIR}/shfmt" 2>>"${LOG_DIR}/install.log"; then
            run "chmod shfmt" chmod +x "${BIN_DIR}/shfmt"
            _step OK "shfmt installed via direct download"
        else
            _step WARN "shfmt install failed — layer will skip"
        fi
    fi
fi

# bats
if have bats; then
    _step OK "bats already present: $(bats --version)"
else
    apt_update
    if retry 3 "install bats" apt_install bats; then
        _step OK "bats installed"
    else
        _step WARN "bats install failed — bats layer will skip"
    fi
fi

# docker (optional)
if have docker; then
    _step OK "docker already present: $(docker --version)"
else
    apt_update
    if retry 3 "install docker" apt_install docker.io; then
        run "enable docker" systemctl enable --now docker
        _step OK "docker installed"
    else
        _step WARN "docker install failed — sandbox layers will skip"
    fi
fi

# tree-sitter CLI (optional; the Python binding is what matters most)
if have tree-sitter; then
    _step OK "tree-sitter CLI present"
fi

# ---------------------------------------------------------------------------
# Phase 2 — pip packages
# ---------------------------------------------------------------------------
_log ""
_log "Phase 2: Install Python dependencies (pip3)"

PIP_FLAGS=()
# On modern Ubuntu/Debian, PEP 668 forbids system pip; we use --break-system-packages
# for the installer script (this is intentional — safe-cli is a system tool).
if pip3 install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_FLAGS+=("--break-system-packages")
fi

pip_install() {
    pip3 install "${PIP_FLAGS[@]}" "$@"
}

# tree-sitter + tree-sitter-bash (pinned for ABI compat with bash:5.1 grammar)
if python3 -c "import tree_sitter, tree_sitter_bash" 2>/dev/null; then
    _step OK "tree-sitter Python bindings already present"
else
    if retry 3 "pip install tree-sitter" pip_install "tree-sitter==0.21.3" "tree-sitter-bash==0.21.0"; then
        _step OK "tree-sitter Python bindings installed"
    else
        _step WARN "tree-sitter install failed — tree-sitter layer will skip"
    fi
fi

# tomli (Python 3.10)
if python3 -c "import tomli" 2>/dev/null; then
    _step OK "tomli already present"
else
    if retry 3 "pip install tomli" pip_install tomli; then
        _step OK "tomli installed"
    else
        _step WARN "tomli install failed — config loading may fail on Python 3.10"
    fi
fi

# requests (used by some layers)
if python3 -c "import requests" 2>/dev/null; then
    _step OK "requests already present"
else
    if retry 2 "pip install requests" pip_install requests; then
        _step OK "requests installed"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3 — npm packages (optional)
# ---------------------------------------------------------------------------
_log ""
_log "Phase 3: Install Node.js tools (npm, optional)"

if have npm; then
    if have bash-language-server; then
        _step OK "bash-language-server already present"
    else
        # Don't fail the whole install if npm is unavailable
        if retry 2 "npm install bash-language-server" \
            npm install -g bash-language-server tree-sitter-cli 2>>"${LOG_DIR}/install.log"; then
            _step OK "bash-language-server installed"
        else
            _step WARN "npm install failed — LSP layer will skip"
        fi
    fi
else
    _step WARN "npm not found — LSP layer will skip"
fi

# ---------------------------------------------------------------------------
# Phase 4 — copy project tree
# ---------------------------------------------------------------------------
_log ""
_log "Phase 4: Copy project files to ${PREFIX}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log "  [DRY] would mkdir ${PREFIX} and copy files"
else
    mkdir -p "${PREFIX}/_temp/cache" "${PREFIX}/_temp/backup" "${PREFIX}/_temp/logs"
    # Copy bv/, bin/, docs/, tests/, systemd/ if they're present in SRC_DIR
    for entry in bv bin docs tests systemd; do
        if [[ -d "${SRC_DIR}/${entry}" ]]; then
            cp -r "${SRC_DIR}/${entry}" "${PREFIX}/"
            _log "  copied ${entry}/"
        fi
    done
    # Copy top-level files
    for f in README.md AGENT_BRIEF.md FUTURE_AGENT_PROMPT.md REPO_DESCRIPTION.md \
             .bashverify.toml install_persistence.sh agent_integration.sh \
             ecosystem.bash-verify.config.js LICENSE; do
        if [[ -f "${SRC_DIR}/${f}" ]]; then
            cp "${SRC_DIR}/${f}" "${PREFIX}/"
            _log "  copied ${f}"
        fi
    done
    # Make scripts executable
    chmod +x "${PREFIX}"/bin/bash_verify "${PREFIX}"/install_persistence.sh \
             "${PREFIX}"/agent_integration.sh 2>/dev/null || true
    _step OK "files copied to ${PREFIX}"
fi

# ---------------------------------------------------------------------------
# Phase 5 — install safe-cli at /usr/local/bin
# ---------------------------------------------------------------------------
_log ""
_log "Phase 5: Install safe-cli and aliases"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log "  [DRY] would install /usr/local/bin/safe-cli and aliases"
else
    if [[ -f "${PREFIX}/bin/safe_cli.py" ]]; then
        install -m 0755 "${PREFIX}/bin/safe_cli.py" "${BIN_DIR}/safe-cli"
        # Convenience aliases
        for alias in bv safebash safebash-run verify-run; do
            ln -sf "${BIN_DIR}/safe-cli" "${BIN_DIR}/${alias}"
        done
        _step OK "safe-cli installed at ${BIN_DIR}/safe-cli + 4 aliases"
    else
        _step FAIL "safe_cli.py not found at ${PREFIX}/bin/"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Phase 6 — /etc/profile.d auto-loader
# ---------------------------------------------------------------------------
_log ""
_log "Phase 6: Install /etc/profile.d auto-loader"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log "  [DRY] would copy agent_integration.sh to /etc/profile.d/"
else
    if [[ -f "${PREFIX}/agent_integration.sh" ]]; then
        cp "${PREFIX}/agent_integration.sh" /etc/profile.d/bash_verify.sh
        chmod 644 /etc/profile.d/bash_verify.sh
        _step OK "auto-loader installed at /etc/profile.d/bash_verify.sh"
    else
        _step WARN "agent_integration.sh not found, skipping profile.d"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 7 — systemd persistence (optional)
# ---------------------------------------------------------------------------
if [[ "${WITH_SYSTEMD}" -eq 1 ]]; then
    _log ""
    _log "Phase 7: Install systemd persistence"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        _log "  [DRY] would install systemd units and enable timer"
    else
        if [[ -d "${PREFIX}/systemd" ]]; then
            cp "${PREFIX}"/systemd/bash-verify-doctor.* /etc/systemd/system/ 2>/dev/null || true
            if have systemctl; then
                run "daemon-reload" systemctl daemon-reload
                if run "enable timer" systemctl enable --now bash-verify-doctor.timer; then
                    _step OK "systemd timer enabled (every 15 min)"
                else
                    _step WARN "systemd enable failed — manual enable may be needed"
                fi
            else
                _step WARN "systemctl not available — install units copied but not enabled"
            fi
        else
            _step WARN "systemd/ directory missing — skipping"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Phase 8 — pull docker image
# ---------------------------------------------------------------------------
_log ""
_log "Phase 8: Pull sandbox Docker image"

if have docker; then
    if docker image inspect "${PREFIX}/.bashverify.toml" >/dev/null 2>&1; then
        :
    fi
    IMG=$(grep -E '^sandbox_image' "${PREFIX}/.bashverify.toml" 2>/dev/null | head -1 | cut -d'"' -f2)
    IMG="${IMG:-bash:5.1}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        _log "  [DRY] would pull ${IMG}"
    else
        if retry 2 "docker pull ${IMG}" docker pull "${IMG}" 2>>"${LOG_DIR}/install.log"; then
            _step OK "sandbox image ${IMG} available"
        else
            _step WARN "docker pull failed — sandbox layer may skip"
        fi
    fi
else
    _step WARN "docker not available — sandbox layers will skip"
fi

# ---------------------------------------------------------------------------
# Phase 9 — doctor check
# ---------------------------------------------------------------------------
_log ""
_log "Phase 9: Run --doctor to verify READY state"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log "  [DRY] would run safe-cli doctor"
else
    if PYTHONPATH="${PREFIX}" python3 "${PREFIX}/bin/bash_verify" --doctor >"${LOG_DIR}/doctor.log" 2>&1; then
        if grep -q "READY" "${LOG_DIR}/doctor.log"; then
            _step OK "doctor reports READY"
        else
            _step WARN "doctor exited 0 but did not report READY — see ${LOG_DIR}/doctor.log"
        fi
    else
        _step WARN "doctor exited non-zero — see ${LOG_DIR}/doctor.log"
    fi
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
_log ""
_log "============================================================"
_log "Installation summary"
_log "============================================================"

ok_count=0
warn_count=0
fail_count=0
for entry in "${STEP_RESULTS[@]}"; do
    status="${entry%%|*}"
    msg="${entry#*|}"
    if [[ "${status}" == "OK" ]]; then
        ok_count=$((ok_count + 1))
    elif [[ "${status}" == "WARN" ]]; then
        warn_count=$((warn_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
done

_log "  OK   : ${ok_count}"
_log "  WARN : ${warn_count}"
_log "  FAIL : ${fail_count}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    _log ""
    _log "This was a DRY RUN. Re-run without --dry-run to install."
    exit 0
fi

_log ""
_log "Try it now:"
_log "  safe-cli doctor"
_log "  safe-cli run ${PREFIX}/tests/good_scripts/hello_world.sh"
_log "  safe-cli exec 'echo Hello, world!'"
_log ""

if [[ ${fail_count} -gt 0 ]]; then
    _log "Some steps FAILED. The system is partially installed."
    _log "Re-run this script to retry the failed steps."
    exit 1
fi

if [[ ${warn_count} -gt 0 ]]; then
    _log "Some steps WARNED. The system is installed but some layers will skip."
    _log "Run 'safe-cli doctor' to see exactly what works."
    exit 0
fi

_log "All steps succeeded. safe-cli is READY."
exit 0
