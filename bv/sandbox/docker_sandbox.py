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
from dataclasses import dataclass, field
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
    # P0-4: cleanup failures surfaced explicitly
    cleanup_failures: list = field(default_factory=list)


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
        argv=None,
        workdir: str = "/work",
        env=None,
        network=None,
        memory=None,
        cpus=None,
        timeout_s=None,
    ):
        """Execute `bash <script> [argv...]` inside a fresh sandbox container.

        P0 7 lifecycle:
          1. docker create  (allocate; no start)
          2. docker start   (begin execution)
          3. supervisor: docker wait <timeout>
          4. on timeout:    docker kill
          5. docker rm --force
          6. verify container gone

        The previous implementation used subprocess.run(..., timeout=...)
        which only killed the client process; the container could
        continue running, leaking resources. The new implementation
        uses docker wait as the supervisor, then docker kill and
        docker rm to guarantee cleanup. The container is destroyed
        even on a 30-second timeout.
        """
        network = network if network is not None else self.config.verify.network_policy
        # Normalize: the old code accepted "deny" as a synonym for "none";
        # keep the same mapping for backward compatibility with configs.
        if network == "deny":
            network = "none"
        memory = memory or self.config.resources.sandbox_memory
        cpus = cpus or self.config.resources.sandbox_cpus
        timeout_s = timeout_s or max(1, self.config.timeouts.sandbox_ms // 1000)

        # Build docker create command (the same as docker run except
        # we split create from start so we can hold the container ID
        # for explicit kill/rm if docker wait times out).
        argv = argv or []
        cmd = [
            self.docker_bin, "create",
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
            "--user=65534:65534",
            "-w", workdir,
        ]
        if env:
            for k, v in env.items():
                cmd += ["-e", f"{k}={redact_secrets(v)}"]
        cmd += [self.image, "bash", "-s", "--"] + argv

        # 1) docker create
        try:
            create_proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            yield SandboxResult(
                exit_code=124, stdout="", stderr="",
                duration_ms=0, timed_out=True,
                error="docker create timed out",
            )
        if create_proc.returncode != 0:
            yield SandboxResult(
                exit_code=create_proc.returncode,
                stdout=create_proc.stdout,
                stderr=create_proc.stderr,
                duration_ms=0,
                error=f"docker create failed: {create_proc.stderr[:500]}",
            )
        container_id = (create_proc.stdout or "").strip()
        if not container_id:
            yield SandboxResult(
                exit_code=1, stdout="", stderr="",
                duration_ms=0,
                error="docker create returned empty container id",
            )

        # 2) docker start
        start = subprocess.run(
            [self.docker_bin, "start", "-i", container_id],
            input=script_content, capture_output=True, text=True, timeout=10,
        )

        # 3) supervisor: docker wait
        wait = subprocess.run(
            [self.docker_bin, "wait", container_id],
            capture_output=True, text=True, timeout=timeout_s + 5,
        )
        timed_out = wait.returncode != 0 or wait.stderr.strip() != ""

        exit_code = 0
        stdout = start.stdout or ""
        stderr = start.stderr or ""
        duration_ms = 0

        if timed_out:
            # 4) docker kill
            try:
                subprocess.run(
                    [self.docker_bin, "kill", container_id],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception as e:
                cleanup_errors.append(f"cleanup: {e!r}")

            # docker wait will now return; capture that
            try:
                wait = subprocess.run(
                    [self.docker_bin, "wait", container_id],
                    capture_output=True, text=True, timeout=5,
                )
                if wait.stdout.strip().isdigit():
                    exit_code = int(wait.stdout.strip())
            except Exception as e:
                cleanup_errors.append(f"cleanup: {e!r}")

            exit_code = exit_code or 124
            duration_ms = timeout_s * 1000
        else:
            # Normal completion. wait.stdout is the exit code.
            try:
                if wait.stdout.strip().isdigit():
                    exit_code = int(wait.stdout.strip())
            except Exception as e:
                cleanup_errors.append(f"Normal completion. wait.stdout is the exit code.: {e!r}")

            # Duration is approximate; we did not time it precisely.
            duration_ms = (wait.returncode or 0) * 0  # placeholder

        # 5) docker rm --force (always, even on success)
        try:
            subprocess.run(
                [self.docker_bin, "rm", "--force", container_id],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as e:
            cleanup_errors.append(f"cleanup: {e!r}")


        # 6) verify container gone
        try:
            inspect = subprocess.run(
                [self.docker_bin, "inspect", container_id],
                capture_output=True, text=True, timeout=5,
            )
            if inspect.returncode == 0:
                # Still there. The system is in a degraded state; record
                # it loudly so the operator can clean up.
                stderr = (stderr + "\nWARNING: sandbox container " +
                           container_id + " was not removed by docker rm").strip()
        except Exception as e:
            cleanup_errors.append(f"docker rm --force: {e!r}")


        yield SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            container_id=container_id,
            cleanup_failures=list(cleanup_errors),
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
