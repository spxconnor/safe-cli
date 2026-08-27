"""Script abstraction with safe backup/restore semantics.

The Script class wraps a Bash source file (or stdin blob) and provides:
- content read/write
- on-disk backup with timestamped directory
- rollback to last backup
- content fingerprint (sha256)
- shebang and metadata detection

Backup policy:
    * All backups are written to a sibling _temp/backup directory.
    * Backups are NEVER deleted by this module. The user may clean them up.
    * restore() always picks the most recent backup that exists.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SHEBANG_RE = re.compile(r"^#!\s*(?P<interp>[^\s]+)(?:\s+(?P<arg>[^\s]+))?")
DEFAULT_BACKUP_ROOT = Path("/opt/bash-verifier/_temp/backup")


@dataclass
class Script:
    path: Optional[Path] = None           # None for stdin-sourced scripts
    content: str = ""                     # current content
    original_content: str = ""            # content at construction time
    backup_paths: list[Path] = field(default_factory=list)
    content_sha256: str = ""   # SHA256 of the bytes that were verified
    shebang: str = ""
    shebang_arg: str = ""
    is_bash: bool = False

    def __post_init__(self) -> None:
        if self.path:
            self.path = Path(self.path)
            if not self.content:
                self.content = self.path.read_text(encoding="utf-8", errors="replace")
        self.original_content = self.content
        self.content_sha256 = self._hash(self.content)
        self._detect_shebang()

    def _detect_shebang(self) -> None:
        first_line = self.content.split("\n", 1)[0] if self.content else ""
        m = SHEBANG_RE.match(first_line)
        if m:
            self.shebang = m.group("interp")
            self.shebang_arg = m.group("arg") or ""
            interp_name = Path(self.shebang).name
            self.is_bash = interp_name in ("bash", "bash5", "bashbug")
        else:
            self.shebang = ""
            self.shebang_arg = ""
            self.is_bash = False

    @staticmethod
    def _hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()

    def update(self, new_content: str) -> None:
        """Update content in memory; persists to disk if path is set.

        Does NOT auto-backup. Call backup() explicitly to capture state first.
        """
        self.content = new_content
        self.content_sha256 = self._hash(new_content)
        self._detect_shebang()
        if self.path:
            self.path.write_text(new_content, encoding="utf-8")

    @property
    def fingerprint(self) -> str:
        """Backwards-compatible alias for content_sha256."""
        return self.content_sha256

    def verify_integrity(self) -> bool:
        """Re-read the file from disk and confirm the SHA256 still matches.

        This is the P0 4 TOCTOU defense: a script file could be
        modified between the time the verifier reads it and the time
        the executor runs it. verify_integrity must be called by
        every execution path between verify and exec, and the executor
        must refuse to run if the SHA256 has changed.
        """
        if not self.path:
            return True  # stdin-sourced scripts cannot be TOCTOU'd on disk
        try:
            current = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return self._hash(current) == self.content_sha256

    def backup(self, label: str = "step") -> Path:
        """Copy current content to a timestamped backup directory."""
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        ns = time.time_ns() % 1_000_000_000
        safe_label = re.sub(r"[^a-zA-Z0-9._-]+", "-", label).strip("-")
        if not safe_label:
            safe_label = "step"
        if self.path:
            base = self.path.stem
            ext = self.path.suffix or ".sh"
        else:
            base = "stdin"
            ext = ".sh"
        fname = f"{base}{ext}"
        backup_dir = DEFAULT_BACKUP_ROOT / f"{safe_label}-{ts}-{ns}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / fname
        backup_path.write_text(self.content, encoding="utf-8")
        meta = backup_dir / "META.txt"
        meta.write_text(
            f"label: {safe_label}\n"
            f"timestamp_utc: {ts}.{ns:09d}\n"
            f"fingerprint: {self.fingerprint}\n"
            f"original_path: {self.path or '<stdin>'}\n"
            f"shebang: {self.shebang} {self.shebang_arg}\n",
            encoding="utf-8",
        )
        self.backup_paths.append(backup_path)
        return backup_path

    def restore_latest(self) -> bool:
        """Restore from the most recent backup. Returns True on success."""
        if not self.backup_paths:
            return False
        latest = self.backup_paths[-1]
        new_content = latest.read_text(encoding="utf-8", errors="replace")
        self.content = new_content
        self.fingerprint = self._hash(new_content)
        self._detect_shebang()
        if self.path:
            self.path.write_text(new_content, encoding="utf-8")
        return True

    def restore_original(self) -> bool:
        """Restore to the content captured at construction time."""
        self.content = self.original_content
        self.fingerprint = self._hash(self.original_content)
        self._detect_shebang()
        if self.path:
            self.path.write_text(self.original_content, encoding="utf-8")
        return True

    def backup_dir(self) -> Optional[Path]:
        if not self.backup_paths:
            return None
        return self.backup_paths[-1].parent


def from_path(path):
    """Build a Script from an on-disk path."""
    return Script(path=Path(path))


def from_content(content, label: str = "stdin"):
    """Build an in-memory Script (path=None) from a content string."""
    return Script(path=None, content=content)


if __name__ == "__main__":
    # Smoke test
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tf:
        tf.write("#!/usr/bin/env bash\necho hello\n")
        p = tf.name
    s = from_path(p)
    print("shebang:", s.shebang, "is_bash:", s.is_bash)
    bp = s.backup("initial")
    print("backup at:", bp)
    s.update("#!/usr/bin/env bash\necho modified\n")
    print("after update fingerprint:", s.fingerprint[:8])
    s.restore_latest()
    print("after restore fingerprint:", s.fingerprint[:8])
    print("content restored matches original:", s.content == s.original_content)
    os.unlink(p)
