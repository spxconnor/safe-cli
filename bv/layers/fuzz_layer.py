"""Layer 10 — Property-based fuzz testing.

Generates random strings of bytes containing combinations of quotes,
slashes, spaces, newlines, shell metacharacters, Unicode, and digits;
runs each in the sandbox against each function.

Failures are saved to the regression corpus so the same input is
replayed on subsequent runs.
"""
from __future__ import annotations

import json
import os
import random
import string
import textwrap
from pathlib import Path
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext
from ..sandbox.docker_sandbox import DockerSandbox


# Bytes that must NEVER appear in shell metacharacter fuzz inputs
# unless they are escaped/encoded properly by the function under test.
_METACHARS = list(' \t\n\r\n\'"\\$`*?[]{}()|&;<>#!~')
_PRINTABLE = string.printable.replace("\x0b", "").replace("\x0c", "")
_SAFE_RANGES = list(_PRINTABLE) + ['\u2603', '\u2600']


class FuzzLayer(Layer):
    name = "fuzz"
    description = "Property-based fuzz testing with regression corpus"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        functions = self._extract_function_names(script)
        if not functions:
            result.status = "skip"
            result.notes.append("no functions found to fuzz")
            return result

        try:
            sb = DockerSandbox(self.config)
        except Exception as e:  # noqa: BLE001
            # P0 8 fix: a skipped layer is INCOMPLETE coverage, not
            # a pass. The safe execution path must refuse to run
            # when the security boundary was never exercised.
            result.status = "incomplete"
            result.notes.append(
                f"Docker sandbox unavailable: {e}. fuzz "
                "coverage is INCOMPLETE; the safe execution path "
                "must refuse to run."
            )
            return result

        seed = int(context.extra.get("fuzz_seed", 0)) if context else 0
        rng = random.Random(seed)
        iterations = int(context.extra.get("fuzz_iterations", self.config.resources.fuzz_iterations)) if context else self.config.resources.fuzz_iterations
        max_bytes = self.config.resources.fuzz_max_input_bytes

        corpus_dir = Path(self.config.paths.fuzz_corpus)
        corpus_dir.mkdir(parents=True, exist_ok=True)

        failures = []
        for i in range(iterations):
            inp = self._generate(rng, max_bytes)
            test_script = self._build_one_shot(script, functions, inp)
            timeout_s = max(1, min(5, self.config.timeouts.sandbox_ms // 1000))
            with sb.run_script(test_script, timeout_s=timeout_s) as sr:
                if sr.timed_out:
                    failures.append({"input": inp, "reason": "timeout", "stderr": sr.stderr[-200:]})
                    continue
                if os.path.exists("/tmp/pwned") or "/tmp/pwned" in (sr.stdout + sr.stderr):
                    failures.append({"input": inp, "reason": "injection", "stderr": sr.stderr[-200:]})
                    continue
                # The test script prints BV_FUZZ_RC=<n>
                for line in sr.stdout.splitlines():
                    if line.startswith("BV_FUZZ_RC="):
                        try:
                            rc = int(line.split("=", 1)[1])
                        except ValueError:
                            continue
                        if rc not in (0, 1):
                            failures.append({"input": inp, "reason": f"rc={rc}", "stderr": sr.stderr[-200:]})
                        break

        # Persist failures to the regression corpus
        if failures:
            crash_path = corpus_dir / f"crash-{os.getpid()}-{seed}.json"
            crash_path.write_text(json.dumps(failures, indent=2), encoding="utf-8")

            for f in failures:
                result.add(self._diag(
                    tool="fuzz",
                    category=Category.SECURITY,
                    severity=Severity.ERROR,
                    message=f"Fuzz failure: {f['reason']}",
                    raw=json.dumps(f)[:500],
                    code="FUZZ_FAIL",
                    suggested_action="quote_variable",
                ))
            result.metadata = {
                "iterations": iterations,
                "failures": len(failures),
                "corpus_file": str(crash_path),
                "seed": seed,
            }
            result.status = "fail"
        else:
            result.metadata = {"iterations": iterations, "failures": 0, "seed": seed}
            result.status = "pass"

        result.duration_ms = self._elapsed()
        return result

    def _extract_function_names(self, script: Script) -> list[str]:
        import re
        names = []
        for m in re.finditer(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{", script.content, re.MULTILINE):
            names.append(m.group(1))
        for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{", script.content, re.MULTILINE):
            if m.group(1) not in names:
                names.append(m.group(1))
        return names

    def _generate(self, rng: random.Random, max_bytes: int) -> str:
        # Mix of strategies so we cover both tiny edge cases and big payloads.
        strategies = ["tiny", "whitespace", "metachar", "unicode", "long"]
        s = rng.choice(strategies)
        if s == "tiny":
            return rng.choice(["", " ", "a", "0", "-", "/", "\t"])
        if s == "whitespace":
            n = rng.randint(1, 16)
            return "".join(rng.choice([" ", "\t", "\n", "\r"]) for _ in range(n))
        if s == "metachar":
            n = rng.randint(1, 32)
            return "".join(rng.choice(_METACHARS + list(string.ascii_letters)) for _ in range(n))
        if s == "unicode":
            return "".join(rng.choice(_SAFE_RANGES) for _ in range(rng.randint(1, 32)))
        # long
        return "".join(rng.choice(_SAFE_RANGES) for _ in range(rng.randint(256, max_bytes)))

    def _build_one_shot(self, script: Script, functions: list[str], inp: str) -> str:
        target = script.path.as_posix() if script.path else "/dev/stdin"
        # Use base64 to encode the input so quoting hell stays inside Python.
        import base64
        b64 = base64.b64encode(inp.encode("utf-8", errors="replace")).decode("ascii")
        return textwrap.dedent(f"""
            #!/usr/bin/env bash
            set -u
            TARGET={target!r}
            FUNCTIONS='{json.dumps(functions)}'
            INPUT_B64='{b64}'
            INPUT="$(printf '%s' "$INPUT_B64" | base64 -d)"
            rm -f /tmp/pwned "/tmp/pwned_$$"
            source "$TARGET" 2>/dev/null || true
            rc=0
            for f in $FUNCTIONS; do
                if declare -F "$f" >/dev/null 2>&1; then
                    "$f" "$INPUT" >/dev/null 2>&1 || rc=$?
                fi
            done
            if [ -e /tmp/pwned ] || [ -e "/tmp/pwned_$$" ]; then
                rm -f /tmp/pwned "/tmp/pwned_$$"
                echo "BV_FUZZ_RC=99"
                exit 99
            fi
            echo "BV_FUZZ_RC=$rc"
            exit 0
        """)

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
