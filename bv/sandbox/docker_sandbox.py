"""Docker sandbox wrapper.

Provides a clean interface to run untrusted Bash inside a Docker container
with:
  - read-only root filesystem
  - tmpfs at /tmp
  - network isolation (--network=none by default)
  - memory limit
  - CPU limit
  - pids limit
  - execution timeout
  - automatic cleanup

The sandbox never mounts the host root filesystem, never has access to
SSH keys, never has access to the real $HOME, and never runs privileged.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from ..config import Config
from ..security.redaction import redact_secrets


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    killed: bool = False
    container_id: str = ""
    error: str = ""


class DockerSandbox:
    """Run Bash scripts in a hard-sandboxed Docker container."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.image = config.verify.sandbox_image
        self.docker_bin = config.tools.docker
        if not Path(self.docker_bin).exists():
            raise RuntimeError(f"docker binary not found at {self.docker_bin}")
        # Ensure image is pulled
        self._ensure_image()

    def _ensure_image(self) -> None:
        # Check if image already present
        proc = subprocess.run(
            [self.docker_bin, "image", "inspect", self.image],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return
        pull = subprocess.run(
            [self.docker_bin, "pull", self.image],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if pull.returncode != 0:
            raise RuntimeError(f"docker pull failed for {self.image}: {pull.stderr}")

    @contextmanager
    def run_script(
        self,
        script_content: str,
        *,
        argv: list[str] | None = None,
        workdir: str = "/work",
        env: dict[str, str] | None = None,
        network: Optional[str] = None,  # default "none" disables networking
        memory: Optional[str] = None,
        cpus: Optional[str] = None,
        timeout_s: Optional[int] = None,
    ) -> Iterator[SandboxResult]:
        """Execute `bash <script> [argv...]` inside a fresh sandbox container.

        Yields a SandboxResult; the container is always removed afterwards.
        """
        network = network if network is not None else self.config.verify.network_policy
        if network == "deny":
            network = "none"
        memory = memory or self.config.resources.sandbox_memory
        cpus = cpus or self.config.resources.sandbox_cpus
        timeout_s = timeout_s or max(1, self.config.timeouts.sandbox_ms // 1000)

        # Stage script content via stdin to avoid --volume mounts on host
        argv = argv or []
        cmd = [
            self.docker_bin, "run",
            "--rm",
            "-i",
            f"--network={network}",
            f"--memory={memory}",
            f"--cpus={cpus}",
            f"--pids-limit={self.config.resources.sandbox_pids_limit}",
            "--read-only",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
            "--tmpfs=/work:rw,nosuid,nodev,size=16m",
            "--security-opt=no-new-privileges",
            "--cap-drop=ALL",
            "--user=65534:65534",   # nobody
            "-w", workdir,
        ]
        if env:
            for k, v in env.items():
                cmd += ["-e", f"{k}={redact_secrets(v)}"]
        cmd.append(self.image)
        cmd += ["bash", "-s", "--"] + argv

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=script_content,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            yield SandboxResult(
                exit_code=124,
                stdout=(e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                stderr=(e.stderr or b"").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
                duration_ms=duration_ms,
                timed_out=True,
                error=f"Sandbox exceeded {timeout_s}s timeout",
            )
            return

        duration_ms = int((time.monotonic() - start) * 1000)
        yield SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_ms=duration_ms,
        )

    def available(self) -> bool:
        return Path(self.docker_bin).exists() and shutil.which(self.docker_bin) is not None


def quick_test(config: Config, script: str) -> SandboxResult:
    """Convenience: run a one-shot Bash script in the sandbox and return the result."""
    with DockerSandbox(config).run_script(script) as r:
        return r


if __name__ == "__main__":
    from ..config import load_config
    cfg = load_config()
    with DockerSandbox(cfg).run_script("echo HELLO_FROM_SANDBOX; date -u +%FT%TZ") as r:
        print(json.dumps(r.__dict__, indent=2))
