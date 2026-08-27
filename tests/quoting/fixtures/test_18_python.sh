# Section 28 fixture: Bash -> python. Inline Python is its own
# language; quoting repair is unsafe.
python3 -c "import sys; print(sys.argv[1])" "$ARG"
