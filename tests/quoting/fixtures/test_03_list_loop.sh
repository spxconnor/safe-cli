# Section 68 mandatory regression fixture #3:
# for x in $LIST — intentional list semantics.
# Engine MUST NOT rewrite this to "$LIST".
for x in $LIST; do
    echo "$x"
done
