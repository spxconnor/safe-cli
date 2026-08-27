"""Configuration loader for bash_verify.

Reads a TOML config file (default: /opt/bash-verifier/.bashverify.toml)
and exposes typed access to settings.

Python 3.10 uses the `tomli` backport; 3.11+ uses the stdlib `tomllib`.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib as _toml  # Python 3.11+
except ImportError:
    import tomli as _toml    # Python 3.10 fallback


DEFAULT_CONFIG_PATH = Path("/opt/bash-verifier/.bashverify.toml")


@dataclass(frozen=True)
class Timeouts:
    tree_sitter_ms: int = 5000
    bash_n_ms: int = 5000
    shellcheck_ms: int = 15000
    lsp_ms: int = 10000
    shfmt_ms: int = 5000
    bats_ms: int = 60000
    sandbox_ms: int = 30000
    fuzz_total_ms: int = 60000
    adversarial_ms: int = 30000
    side_effects_ms: int = 30000


@dataclass(frozen=True)
class Resources:
    sandbox_memory: str = "256m"
    sandbox_cpus: str = "1.0"
    sandbox_pids_limit: int = 256
    fuzz_iterations: int = 200
    fuzz_max_input_bytes: int = 4096


@dataclass(frozen=True)
class Paths:
    log_dir: str = "/opt/bash-verifier/_temp/logs"
    regression_corpus: str = "/opt/bash-verifier/tests/adversarial_corpus"
    fuzz_corpus: str = "/opt/bash-verifier/tests/fuzz_corpus"
    broken_examples: str = "/opt/bash-verifier/tests/broken_scripts"


@dataclass(frozen=True)
class Tools:
    shellcheck: str = "/usr/bin/shellcheck"
    shfmt: str = "/usr/local/bin/shfmt"
    bats: str = "/usr/bin/bats"
    bash_language_server: str = "bash-language-server"
    docker: str = "/usr/bin/docker"
    bash: str = "/bin/bash"
    python3: str = "/usr/bin/python3"
    node: str = "/usr/bin/node"


@dataclass(frozen=True)
class VerifySettings:
    self_healing: bool = True
    max_repair_attempts: int = 3
    max_identical_diagnostics: int = 4
    max_total_seconds: int = 180
    severity_threshold: str = "warning"
    network_policy: str = "none"
    sandbox_image: str = "bash:5.1"


@dataclass(frozen=True)
class ReportingSettings:
    human_readable: bool = True
    json_output: bool = False
    redact_secrets: bool = True


@dataclass(frozen=True)
class CacheSettings:
    enabled: bool = True
    dir: str = "/opt/bash-verifier/_temp/cache"
    ttl_seconds: int = 3600


@dataclass(frozen=True)
class Config:
    verify: VerifySettings = field(default_factory=VerifySettings)
    timeouts: Timeouts = field(default_factory=Timeouts)
    resources: Resources = field(default_factory=Resources)
    paths: Paths = field(default_factory=Paths)
    tools: Tools = field(default_factory=Tools)
    reporting: ReportingSettings = field(default_factory=ReportingSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)
    source_path: str = ""


def _coerce(ctor, raw: dict):
    kwargs = {}
    for f in ctor.__dataclass_fields__.values():
        if f.name in raw:
            kwargs[f.name] = raw[f.name]
    return ctor(**kwargs)


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load configuration from a TOML file, falling back to defaults."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw: dict = {}
    if config_path.exists():
        with open(config_path, "rb") as f:
            raw = _toml.load(f)
    verify = _coerce(VerifySettings, raw.get("verify", {}))
    timeouts = _coerce(Timeouts, raw.get("timeouts", {}))
    resources = _coerce(Resources, raw.get("resources", {}))
    paths = _coerce(Paths, raw.get("paths", {}))
    tools = _coerce(Tools, raw.get("tools", {}))
    reporting = _coerce(ReportingSettings, raw.get("reporting", {}))
    cache = _coerce(CacheSettings, raw.get("cache", {}))
    return Config(
        verify=verify,
        timeouts=timeouts,
        resources=resources,
        paths=paths,
        tools=tools,
        reporting=reporting,
        cache=cache,
        source_path=str(config_path),
    )


if __name__ == "__main__":
    cfg = load_config()
    print(f"Loaded config from: {cfg.source_path}")
    print(f"Sandbox image: {cfg.verify.sandbox_image}")
    print(f"Network policy: {cfg.verify.network_policy}")
    sys.exit(0)
