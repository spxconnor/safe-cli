# Section 68 mandatory regression fixture #10:
# Heredoc body in unquoted-tag form. Body IS expanded, but it's NOT a
# place where quoting rules apply (it's the body, not a command arg).
cat <<EOF
$HOME
EOF
