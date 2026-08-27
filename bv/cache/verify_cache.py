"""Verification result cache.

Hashes the script content + tool versions + config + test suite to form
a cache key. Caches only STATIC analysis results (which are deterministic
given the same inputs); runtime / sandbox results are NOT cached.
"""
from __future__ import annotations

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
    h = hashlib.sha256()
    h.update(layer.encode())
    h.update(script_content.encode("utf-8", errors="replace"))
    # Include relevant config knobs
    h.update(json.dumps({
        "severity_threshold": config.verify.severity_threshold,
        "shfmt_opts": ["-i", "2", "-ci", "-bn", "-sr"],
    }, sort_keys=True).encode())
    return h.hexdigest()


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
