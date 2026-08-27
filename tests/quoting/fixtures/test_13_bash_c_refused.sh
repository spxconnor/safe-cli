# bash -c is a dynamic execution sink. Quoting alone is not enough.
# This is section 53 of the spec.
CMD="$1"
bash -c "$CMD"
