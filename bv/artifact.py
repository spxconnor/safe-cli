"""Immutable artifact for path-free execution.

An Artifact is a (sha256, content) pair that the executor can run
without ever touching the source path. The SHA256 is the verified
identity; the content is the bytes the executor runs.

This is the P0 4 fix: the verified artifact is bound to its content
hash and the executor operates on bytes, not a path. The original
file may change or be deleted; the Artifact remains stable.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Artifact:
    """A content-addressed, immutable Bash artifact."""
    content: bytes
    sha256: str

    @classmethod
    def from_text(cls, text: str) -> "Artifact":
        b = text.encode("utf-8")
        return cls(content=b, sha256=hashlib.sha256(b).hexdigest())

    @classmethod
    def from_bytes(cls, b: bytes) -> "Artifact":
        return cls(content=b, sha256=hashlib.sha256(b).hexdigest())

    def __post_init__(self) -> None:
        # Frozen dataclass: verify content matches the declared SHA256.
        actual = hashlib.sha256(self.content).hexdigest()
        if actual != self.sha256:
            raise ValueError(
                f"Artifact sha256 mismatch: declared {self.sha256[:12]}..., "
                f"actual {actual[:12]}..."
            )
