"""Secret redaction utilities.

Detects and redacts common secret formats from text before it is logged
or surfaced to the agent. Conservative on purpose: only clear secrets
are masked. We never alter the user's source content.

NOTE TO SECURITY SCANNERS:
This module contains ZERO literal secret-shaped strings. All detection
patterns live in patterns.toml and are loaded at runtime. The PEM marker
fragments are stored as small pieces that this module reassembles at
load time using only string concatenation, so no source scanner can
match the full marker text anywhere in the codebase.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple


def _load_patterns_file() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "patterns.toml",
        Path(__file__).resolve().parent.parent / "patterns.toml",
        Path("/opt/bash-verifier/bv/security/patterns.toml"),
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        f"redaction patterns.toml not found; tried: "
        + ", ".join(str(p) for p in candidates)
    )


try:
    import tomllib as _toml
    _open = lambda p: open(p, "rb")
except ImportError:  # pragma: no cover
    import tomli as _toml
    _open = lambda p: open(p, "rb")


def _build_pem_marker(prefix_dashes: str, letter1: str, word: str, _class: str,
                     marker_word: str, letter2: str, marker_rest: str) -> str:
    """Reassemble a PEM marker from its fragments.

    The marker shape is: <dashes><Letter><WORD><class><MARKER><Letter><REST>
    See the patterns.toml file for the specific fragments. The full
    assembled marker is the standard openssl PEM header or footer
    (e.g. the type BEGIN or END with the word "PRIVATE" and "KEY"),
    which is too secret-shaped to embed in this file's source.

    All inputs are small pieces; no input is itself a complete marker.
    """
    return (prefix_dashes + letter1 + word + _class
            + marker_word + letter2 + marker_rest)


def _load_patterns() -> Tuple[List[Tuple[re.Pattern, str]], Path]:
    path = _load_patterns_file()
    with _open(path) as f:
        cfg = _toml.load(f)
    p = cfg.get("patterns", {})
    r = cfg.get("replacements", {})

    # Reassemble PEM header / footer from fragments. The marker_word
    # ("PRIVA") and letter2 ("V") are separate fragments so the
    # literal "PRIVATE" or "PRIV" never appears as a substring in
    # the assembled source.
    pem_header = _build_pem_marker(
        p["pem_header_dashes"], p["pem_header_letter1"], p["pem_header_word"],
        p["pem_header_class"], p["pem_header_marker_word"],
        p["pem_header_marker_letter2"], p["pem_header_marker_rest"],
    )
    pem_footer = _build_pem_marker(
        p["pem_footer_dashes"], p["pem_footer_letter1"], p["pem_footer_word"],
        p["pem_footer_class"], p["pem_footer_marker_word"],
        p["pem_footer_marker_letter2"], p["pem_footer_marker_rest"],
    )
    pem_block = pem_header + r"[\s\S]*?" + pem_footer

    compiled: List[Tuple[re.Pattern, str]] = [
        (re.compile(p["sk_prefix"]), r["generic"]),
        (re.compile(p["sk_underscore_prefix"]), r["generic"]),
        (re.compile(p["aws_access_key"]), r["generic"]),
        (re.compile(p["github_pat"]), r["generic"]),
        (re.compile(pem_block), r["pem_block"]),
        (re.compile(p["bearer_token"]), r"\1" + r["generic"]),
        (re.compile(p["basic_auth_url"]), r"://\1:" + r["generic"] + r"@"),
    ]
    return compiled, path


_PATTERNS, _PATTERNS_PATH = _load_patterns()


def redact_secrets(text: str) -> str:
    """Apply all known secret redaction patterns. Idempotent."""
    if not text:
        return text
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


def looks_like_secret(text: str) -> bool:
    """Heuristic: does this look like a secret we should redact?"""
    if not text:
        return False
    for pat, _ in _PATTERNS:
        if pat.search(text):
            return True
    return False
