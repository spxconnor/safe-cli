# Section 28 fixture: Bash -> awk. The awk program is its own
# language; quoting repair is unsafe.
awk -F: '{print $1}' /etc/passwd
