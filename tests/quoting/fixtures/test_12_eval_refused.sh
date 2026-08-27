# eval is a dynamic execution sink. Engine MUST refuse quoting-only fixes.
# This is section 52 of the spec.
USER_INPUT="$1"
eval "$USER_INPUT"
