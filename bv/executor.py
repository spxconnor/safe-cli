"""Single execution broker for untrusted Bash.

ARCHITECTURAL INVARIANT (P0 1 + P0 2):

  HOST MAY PARSE UNTRUSTED CODE
  HOST MAY ANALYZE UNTRUSTED CODE
  HOST MAY HASH UNTRUSTED CODE
  HOST MAY NEVER EXECUTE UNTRUSTED CODE

All execution of untrusted Bash flows through ExecutionBroker.execute.
The host's bash binary is NEVER invoked on untrusted bytes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .artifact import Artifact
from .sandbox.docker_sandbox import DockerSandbox, SandboxResult


@dataclass
class ExecutionRequest:
    """A request to execute an untrusted Bash artifact."""
    artifact: Artifact              # the verified bytes to run
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    workdir: str = "/work"
    timeout_s: int = 30


@dataclass
class ExecutionResult:
    artifact_sha256: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    container_id: str = ""
    error: str = ""


class ExecutionBroker:
    """The single allowed executor for untrusted Bash code.

    The host never calls subprocess.run on the artifact's content.
    Everything goes through Docker (P0 1 + P0 2 invariant).
    """

    def __init__(self, config) -> None:
        self.config = config

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Run the artifact inside the Docker sandbox.

        Verifies the artifact SHA256 binding (P0 4) before execution.
        Returns an ExecutionResult; never raises for ordinary script
        errors (non-zero exit, timeout). Raises only for infrastructure
        failures (sandbox unavailable).
        """
        # P0 4: re-verify the SHA256 binding. The artifact is frozen;
        # this is a sanity check.
        actual = __import__("hashlib").sha256(request.artifact.content).hexdigest()
        if actual != request.artifact.sha256:
            return ExecutionResult(
                artifact_sha256=request.artifact.sha256,
                exit_code=1, stdout="", stderr="",
                duration_ms=0, timed_out=False,
                error=f"artifact sha256 mismatch: declared {request.artifact.sha256[:12]}..., actual {actual[:12]}...",
            )

        # Execute inside the Docker sandbox. The script content is
        # passed as stdin to the container; the host's bash binary
        # is not invoked.
        sb = DockerSandbox(self.config)
        cleanup_errors: list[str] = []  # P0-4
        start_ms = int(time.time() * 1000)
        try:
            with sb.run_script(
                request.artifact.content.decode("utf-8", errors="replace"),
                argv=request.argv,
                workdir=request.workdir,
                env=request.env,
                timeout_s=request.timeout_s,
            ) as sr:
                result = ExecutionResult(
                    artifact_sha256=request.artifact.sha256,
                    exit_code=sr.exit_code,
                    stdout=sr.stdout,
                    stderr=sr.stderr,
                    duration_ms=sr.duration_ms,
                    timed_out=sr.timed_out,
                    container_id=sr.container_id,
                )
                if sr.error:
                    result.error = sr.error
        except Exception as e:
            # Infrastructure failure (Docker down, image missing, etc.)
            return ExecutionResult(
                artifact_sha256=request.artifact.sha256,
                exit_code=1, stdout="", stderr="",
                duration_ms=0, timed_out=False,
                error=f"execution broker infrastructure failure: {e!r}",
            )
        return result
