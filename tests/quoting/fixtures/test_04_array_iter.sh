# Section 68 mandatory regression fixture #4:
# for x in "${LIST[@]}" — already correct array iteration.
for x in "${LIST[@]}"; do
    echo "$x"
done
