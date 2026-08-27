#!/usr/bin/env bash
# A clean, well-written Bash script.
set -euo pipefail

greet() {
    local name="$1"
    echo "Hello, ${name}!"
}

main() {
    local who="${1:-world}"
    greet "$who"
}

main "$@"
