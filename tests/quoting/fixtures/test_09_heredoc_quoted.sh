# Section 68 mandatory regression fixture #9:
# Heredoc body in single-quoted-tag form. Contents are LITERAL.
# Engine MUST NOT scan the body as ordinary Bash.
cat <<'EOF'
$HOME
$(date)
EOF
