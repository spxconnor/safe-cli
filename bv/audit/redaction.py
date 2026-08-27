"""bv/audit/redaction.py - redact secrets before persistence.

Rules:
  - We never log raw credentials, API keys, tokens, passwords, private
    keys, cookie values, or complete sensitive environment variables.
  - All redaction happens before persistence. The actual command and
    runtime environment are NEVER mutated.
  - The redaction patterns are conservative: only clear secrets are
    masked, never the surrounding text.

The patterns here are intentionally similar to those already in
bv/security/redaction.py (the runtime secret filter), so the same
secrets get redacted whether they appear in stdout, env, or argv.
"""
from __future__ import annotations

import re
from typing import Iterable


# (pattern, replacement) pairs. Order matters: more specific first.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # API keys / tokens
    (re.compile(r"sk-[A-Za-z0-9_\-]{20,}"), "sk-***REDACTED***"),
    (re.compile(r"sk_[A-Za-z0-9_\-]{20,}"), "sk_***REDACTED***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***REDACTED***"),
    # GitHub PATs
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "ghp_***REDACTED***"),
    (re.compile(r"github_pat_[A-Za-z0-9_\-]{20,}"), "github_pat_***REDACTED***"),
    # AWS access keys
    (re.compile(r"ASIA[0-9A-Z]{16}"), "ASIA***REDACTED***"),
    # JWTs (three base64url segments separated by dots)
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
     "eyJ***REDACTED***"),
    # PEM private keys (whole block)
    (re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ), "-----REDACTED-PRIVATE-KEY-BLOCK-----"),
    # Bearer auth
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"), "Bearer ***REDACTED***"),
    # Basic auth in URLs
    (re.compile(r"://([^:\s/@]+):([^@\s/]+)@"), r"://\1:***REDACTED***@"),
    # Password in key=value
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*=\s*"
               r"([^\s'\"&;]+)"),
     r"\1=***REDACTED***"),
    # SSH private key markers (without the full body)
    (re.compile(r"BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY"),
     "BEGIN ***REDACTED*** PRIVATE KEY"),
    # Authorization headers
    (re.compile(r"(?i)authorization\s*:\s*([^\r\n]+)"),
     "Authorization: ***REDACTED***"),
    # Cookies
    (re.compile(r"(?i)(set-cookie|cookie)\s*:\s*([^\r\n;]+)"),
     r"\1: ***REDACTED***"),
    # Generic API key=value with quoted value
    (re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?key|token|secret)\s*"
               r"[:=]\s*['\"]?([A-Za-z0-9._\-]{16,})"),
     r"\1: ***REDACTED***"),
]


def redact_text(text: str | None) -> str | None:
    """Redact secrets in a free-form string. Returns the redacted text,
    or None if input was None. Safe to call on any input."""
    if text is None:
        return None
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_argv(argv: Iterable[str] | None) -> list[str] | None:
    """Redact secrets in a command argv. Each element is passed through
    redact_text independently so partial matches are caught."""
    if argv is None:
        return None
    out = []
    for a in argv:
        out.append(redact_text(a) or "")
    return out


def redact_environment(env: dict | None) -> dict:
    """Redact sensitive environment variable values.

    Heuristic: any key whose name looks secret-y (case-insensitive
    contains token, secret, key, password, passwd, auth) has its
    value redacted. Other env values are passed through redact_text
    in case they contain embedded secrets.
    """
    if not env:
        return {}
    secret_key = re.compile(r"(?i)(token|secret|key|password|passwd|auth)")
    out = {}
    for k, v in env.items():
        if secret_key.search(k or ""):
            out[k] = "***REDACTED***"
        else:
            out[k] = redact_text(v) or ""
    return out


def redact_exception(exc: BaseException | None) -> str | None:
    """Redact secrets in an exception's stringified form."""
    if exc is None:
        return None
    return redact_text(f"{type(exc).__name__}: {exc}")
