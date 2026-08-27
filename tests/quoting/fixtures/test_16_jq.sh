# Section 28 / 29 fixture:
# Cross-language boundary Bash -> jq. The repair engine MUST refuse
# any quoting-only fix; the only correct approach is structural
# restructuring (temp file, heredoc, env var).
SELECTOR='.items[] | select(.active)'
jq "$SELECTOR" data.json
