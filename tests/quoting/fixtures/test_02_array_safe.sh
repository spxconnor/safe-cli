# Section 68 mandatory regression fixture #2:
# Array iteration with ${FILES[@]} MUST NOT be touched.
FILES=(a b c)
printf '%s\n' "${FILES[@]}"
