"""Verification result cache.

Hashes the script content + tool versions + config + test suite to form
a cache key. Caches only STATIC analysis results (which are deterministic
given the same inputs); runtime / sandbox results are NOT cached.
"""
from __future__ import annotations
import sys

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from ..config import Config
from ..diagnostic import Diagnostic, LayerResult, deserialize_diagnostics


CACHEABLE_LAYERS = {"tree_sitter", "bash_n", "shellcheck", "shfmt", "lsp"}


def _hash_inputs(script_content: str, config: Config, layer: str) -> str:
    """Stable short hash for caching a layer result.

    P1-19: includes the environment snapshot (safe-cli version,
    tool versions, Python runtime, config hash, sandbox image) so
    that changes to any of those inputs invalidate cached results.
    """
    h = hashlib.sha256()
    h.update(layer.encode())
    h.update(script_content.encode("utf-8", errors="replace"))
    # Include relevant config knobs
    h.update(json.dumps({
        "severity_threshold": config.verify.severity_threshold,
        "shfmt_opts": ["-i", "2", "-ci", "-bn", "-sr"],
    }, sort_keys=True).encode())
    # P1-19: environment snapshot so tool/config changes invalidate cache
    snap = environment_snapshot(config)
    h.update(json.dumps(snap, sort_keys=True).encode())
    return h.hexdigest()



# P1-19: capture a small "environment snapshot" that goes into the
# cache key. If any of these inputs change, cached results are
# invalidated.
_SAFE_CLI_VERSION = "1.0.0"


def _tool_version(tool_path: str) -> str:
    """Return the version string of an external tool, or "" if missing."""
    try:
        r = subprocess.run(
            [tool_path, "--version"],
            capture_output=True, text=True, timeout=2,
        )
        out = (r.stdout or r.stderr or "").strip()
        return out.splitlines()[0] if out else ""
    except Exception:
        return ""


def environment_snapshot(config=None) -> dict:
    """Capture a small dict of versions and config fingerprint.

    Used as a component of the cache key. If any field changes, the
    cache key changes and old results are no longer reused.
    """
    cfg = config
    if cfg is None:
        try:
            from ..config import load_config
            cfg = load_config()
        except Exception:
            cfg = None
    snap = {
        "safe_cli_version": _SAFE_CLI_VERSION,
        "shellcheck_version": _tool_version("shellcheck"),
        "shfmt_version": _tool_version("shfmt"),
        "bats_version": _tool_version("bats"),
        "python_version": sys.version.split()[0],
        "sandbox_image": cfg.verify.sandbox_image if cfg else "",
    }
    if cfg is not None:
        try:
            import hashlib
            cfg_repr = repr(sorted(cfg.to_dict().items())) if hasattr(cfg, "to_dict") else repr(cfg)
            snap["config_hash"] = hashlib.sha256(cfg_repr.encode()).hexdigest()[:12]
        except Exception:
            snap["config_hash"] = ""
    return snap


def environment_fingerprint(config=None) -> str:
    """Stable short hash of the environment snapshot, for cache keys."""
    import hashlib
    import json
    snap = environment_snapshot(config)
    payload = json.dumps(snap, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def cache_key(script_content: str, config: Config, layer: str) -> str:
    return _hash_inputs(script_content, config, layer)


def cache_path(config: Config, key: str, layer: str) -> Path:
    base = Path(config.cache.dir)
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{layer}-{key}.json"


def cache_get(script_content: str, config: Config, layer: str) -> Optional[LayerResult]:
    if not config.cache.enabled or layer not in CACHEABLE_LAYERS:
        return None
    key = cache_key(script_content, config, layer)
    p = cache_path(config, key, layer)
    if not p.exists():
        return None
    age = time.time() - p.stat().st_mtime
    if age > config.cache.ttl_seconds:
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if d.get("key") != key:
        return None
    result = LayerResult(
        layer=layer,
        status=d["status"],
        duration_ms=d.get("duration_ms", 0),
        notes=d.get("notes", []),
        metadata=d.get("metadata", {}),
    )
    result.diagnostics = deserialize_diagnostics(json.dumps(d.get("diagnostics", [])))
    return result


def cache_put(result: LayerResult, script_content: str, config: Config) -> None:
    if not config.cache.enabled or result.layer not in CACHEABLE_LAYERS:
        return
    key = cache_key(script_content, config, result.layer)
    p = cache_path(config, key, result.layer)
    payload = {
        "key": key,
        "status": result.status,
        "duration_ms": result.duration_ms,
        "notes": result.notes,
        "metadata": result.metadata,
        "diagnostics": [d.to_dict() for d in result.diagnostics],
        "stored_at": time.time(),
    }
    p.write_text(json.dumps(payload), encoding="utf-8")


def cache_clear(config: Config, layer: Optional[str] = None) -> int:
    """Remove cache entries. Returns the count removed. Caller must NOT use rm."""
    base = Path(config.cache.dir)
    if not base.exists():
        return 0
    removed = 0
    # Move files to a sibling _trash directory; never call rm.
    trash = base / "_trash"
    trash.mkdir(parents=True, exist_ok=True)
    pattern = f"{layer}-" if layer else ""
    for p in base.glob(f"{pattern}*.json"):
        target = trash / p.name
        p.rename(target)
        removed += 1
    return removed
