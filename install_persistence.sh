#!/usr/bin/env bash
# Install bash_verify as a boot-persistent service.
#
# Two options:
#   systemd: installs a service + timer
#   pm2:     installs a cron job via PM2
#
# Both install to /opt/bash-verifier and never modify user data.
#
# Usage:
#   /opt/bash-verifier/install_persistence.sh systemd
#   /opt/bash-verifier/install_persistence.sh pm2

set -euo pipefail

MODE="${1:-systemd}"

BV_DIR="/opt/bash-verifier"
BV_BIN="${BV_DIR}/bin/bash_verify"

if [[ ! -x "${BV_BIN}" ]]; then
    echo "ERROR: ${BV_BIN} not found or not executable" >&2
    exit 1
fi

case "${MODE}" in
    systemd)
        echo "[install_persistence] installing systemd unit + timer..."
        cp "${BV_DIR}/systemd/bash-verify-doctor.service" /etc/systemd/system/
        cp "${BV_DIR}/systemd/bash-verify-doctor.timer" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now bash-verify-doctor.timer
        systemctl status bash-verify-doctor.timer --no-pager
        echo
        echo "OK. The doctor check will run every 15 minutes."
        echo "Inspect with:  systemctl list-timers bash-verify-doctor.timer"
        echo "Last result:   journalctl -u bash-verify-doctor.service -n 50"
        ;;

    pm2)
        echo "[install_persistence] registering PM2 cron job..."
        if ! command -v pm2 >/dev/null 2>&1; then
            echo "ERROR: pm2 not found on PATH" >&2
            exit 1
        fi
        pm2 start "${BV_DIR}/ecosystem.bash-verify.config.js"
        pm2 save
        pm2 startup systemd 2>&1 | tail -5 || true
        echo
        echo "OK. PM2 will run --doctor every 15 minutes."
        echo "Inspect with:  pm2 status && pm2 logs bash-verify-doctor"
        ;;

    *)
        echo "Usage: $0 {systemd|pm2}" >&2
        exit 2
        ;;
esac
