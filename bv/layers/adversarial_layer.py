"""Layer 9 — Adversarial quoting and hostile input test suite.

For each function in the script that accepts string input, this layer
runs the function with a corpus of pathological inputs to detect quoting
bugs, command injection, and pathname expansion problems.

Examples of pathological inputs:
  empty string, single char, spaces, tabs, newlines
  single quotes, double quotes, backslashes, dollar signs
  asterisks, question marks, square brackets
  $(echo injected), `echo injected`
  leading hyphens, leading slashes
  very long strings, carriage returns, Unicode
  multiple consecutive whitespaces

The layer runs the tests inside the Docker sandbox with network disabled.
"""
from __future__ import annotations

import base64
import json
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext
from ..sandbox.docker_sandbox import DockerSandbox


HOSTILE_CORPUS = [
    "",
    "a",
    "hello",
    "hello world",
    "hello\tworld",
    "hello\nworld",
    "hello\rworld",
    "hello'world",
    'hello"world',
    "hello\\world",
    "hello$world",
    "hello`world`",
    "$(echo injected)",
    "`echo injected`",
    "foo; echo injected",
    "foo && echo injected",
    "foo | echo injected",
    "foo || echo injected",
    "*",
    "?",
    "[abc]",
    "--help",
    "../../tmp/test",
    "$HOME",
    "${HOME}",
    "$(touch /tmp/pwned)",
    "`touch /tmp/pwned`",
    "a" * 4096,
    "   \t\n\r   ",
    "-rf",
    "--version",
    "/etc/passwd",
    "CON",
    "NUL",
    "\x00null\x00",
    "unicode \u2603 snowman",
    "with NUL\x00byte",
    "with CRLF\r\n",
    "with ANSI \x1b[31mred",
]


# Bash test script template. Uses {{ }} for Python-side substitution
# so f-strings can be used safely without brace collisions.
_BASH_TEMPLATE = r"""#!/usr/bin/env bash
set -u
TARGET={{TARGET}}
CORPUS_B64={{CORPUS_B64}}
FUNCTIONS_B64={{FUNCTIONS_B64}}

decode() {
    printf '%s' "$1" | base64 -d
}

CORPUS_JSON="$(decode "$CORPUS_B64")"
FUNCTIONS_JSON="$(decode "$FUNCTIONS_B64")"

# source target
source "$TARGET" 2>/dev/null || true

# Build function list from JSON
mapfile -t FUNCS < <(printf '%s\n' "$FUNCTIONS_JSON" | python3 -c 'import sys,json
for x in json.load(sys.stdin):
    print(x)')

LEN=$(printf '%s' "$CORPUS_JSON" | python3 -c 'import sys,json
print(len(json.load(sys.stdin)))')

for f in "${FUNCS[@]}"; do
    if ! declare -F "$f" >/dev/null 2>&1; then
        continue
    fi
    idx=0
    while [ "$idx" -lt "$LEN" ]; do
        INPUT=$(printf '%s' "$CORPUS_JSON" | python3 -c '
import sys, json
data = json.load(sys.stdin)
print(repr(data[int(sys.argv[1])]))
' "$idx")
        idx=$((idx + 1))

        rm -f /tmp/pwned "/tmp/pwned_$$"
        "$f" "$INPUT" >/dev/null 2>&1 || rc=$?

        reason=""
        ok=1
        if [ -e /tmp/pwned ] || [ -e "/tmp/pwned_$$" ]; then
            reason="function executed injected command"
            ok=0
            rm -f /tmp/pwned "/tmp/pwned_$$"
        fi

        printf 'BV_TEST_RESULT %s\n' "$(python3 -c '
import json, sys
rec = {"func": sys.argv[1], "input": sys.argv[2], "ok": bool(int(sys.argv[3])), "reason": sys.argv[4]}
print(json.dumps(rec))
' "$f" "$INPUT" "$ok" "$reason")"
    done
done
"""


class AdversarialLayer(Layer):
    name = "adversarial"
    description = "Adversarial quoting + hostile input corpus"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        functions = self._extract_function_names(script)
        if not functions:
            result.status = "skip"
            result.notes.append("no functions found to test adversarially")
            return result

        try:
            sb = DockerSandbox(self.config)
        except Exception as e:  # noqa: BLE001
            # P0 8 fix: a skipped layer is INCOMPLETE coverage, not
            # a pass. The safe execution path must refuse to run
            # when the security boundary was never exercised.
            result.status = "incomplete"
            result.notes.append(
                f"Docker sandbox unavailable: {e}. adversarial "
                "coverage is INCOMPLETE; the safe execution path "
                "must refuse to run."
            )
            return result

        test_script = self._build_test_script(script, functions)
        timeout_s = max(1, self.config.timeouts.adversarial_ms // 1000)

        with self._timer():
            with sb.run_script(test_script, timeout_s=timeout_s) as sr:
                result.metadata["exit_code"] = sr.exit_code
                result.metadata["stdout_tail"] = sr.stdout[-4000:]
                result.metadata["stderr_tail"] = sr.stderr[-2000:]
                result.metadata["duration_ms"] = sr.duration_ms

                passed = 0
                failed = 0
                for line in sr.stdout.splitlines():
                    line = line.strip()
                    if not line.startswith("BV_TEST_RESULT "):
                        continue
                    try:
                        rec = json.loads(line[len("BV_TEST_RESULT "):])
                    except json.JSONDecodeError:
                        continue
                    if rec.get("ok"):
                        passed += 1
                    else:
                        failed += 1
                        result.add(self._diag(
                            tool="adversarial",
                            category=Category.SECURITY,
                            severity=Severity.ERROR,
                            message=(
                                f"Function '{rec['func']}' mishandled input "
                                f"{rec['input']!r}: {rec['reason']}"
                            ),
                            code="ADVERSARIAL_FAIL",
                            raw=rec.get("evidence", ""),
                            suggested_action="quote_variable",
                        ))

                result.metadata["passed"] = passed
                result.metadata["failed"] = failed
                result.status = "pass" if failed == 0 else "fail"

        result.duration_ms = self._elapsed()
        return result

    def _extract_function_names(self, script: Script) -> list[str]:
        """Find Bash function names via a simple regex — good enough for the
        corpus test, not a substitute for an AST parse."""
        import re
        text = script.content
        names = []
        for m in re.finditer(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{", text, re.MULTILINE):
            names.append(m.group(1))
        for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{", text, re.MULTILINE):
            if m.group(1) not in names:
                names.append(m.group(1))
        return names

    def _build_test_script(self, script: Script, functions: list[str]) -> str:
        """Fill in the {{TARGET}}, {{CORPUS_B64}}, {{FUNCTIONS_B64}} placeholders."""
        target = script.path.as_posix() if script.path else "/dev/stdin"
        corpus_b64 = base64.b64encode(json.dumps(HOSTILE_CORPUS).encode()).decode()
        functions_b64 = base64.b64encode(json.dumps(functions).encode()).decode()
        out = _BASH_TEMPLATE
        out = out.replace("{{TARGET}}", target)
        out = out.replace("{{CORPUS_B64}}", corpus_b64)
        out = out.replace("{{FUNCTIONS_B64}}", functions_b64)
        return out

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
