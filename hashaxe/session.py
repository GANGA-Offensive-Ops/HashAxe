# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/session.py
#  Hashaxe session persistence for resuming interrupted cracking operations.
#  Saves progress to JSON session files with key hash verification.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
session.py — Hashaxe session persistence.

Saves progress to a .session JSON file so interrupted cracks can resume
from where they left off rather than starting over.

Session files are stored in ~/.config/hashaxe/sessions/ by default,
or in the current directory if XDG_CONFIG_HOME is not set.

Session file format (JSON):
{
    "version":      1,
    "session_id":   "abc123",
    "key_path":     "/path/to/key",
    "key_hash":     "sha256:abc...",   -- hash of key file to detect changes
    "wordlist":     "/path/to/wordlist",
    "mode":         "wordlist|mask|hybrid",
    "use_rules":    true,
    "rule_file":    null,
    "mask":         null,
    "bytes_done":   12345678,          -- byte offset in wordlist
    "words_tried":  500000,
    "start_time":   1706000000.0,
    "elapsed":      3600.5,
    "last_updated": 1706003600.0
}
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# ── Session data ──────────────────────────────────────────────────────────────

@dataclass
class Session:
    """All state needed to pause and resume a cracking session."""

    version:      int   = 2
    session_id:   str   = field(default_factory=lambda: uuid.uuid4().hex[:12])
    key_path:     str   = ""
    key_hash:     str   = ""       # sha256 of key bytes — detect stale sessions
    wordlist:     str   = ""
    mode:         str   = "wordlist"  # wordlist | mask | hybrid
    use_rules:    bool  = False
    rule_file:    str | None = None
    mask:         str | None = None
    bytes_done:   int   = 0        # byte offset reached in wordlist
    words_tried:  int   = 0        # total candidates tested
    start_time:   float = field(default_factory=time.time)
    elapsed:      float = 0.0      # cumulative seconds (survives restarts)
    last_updated: float = field(default_factory=time.time)

    # ── Persistence path ──────────────────────────────────────────────────────

    @staticmethod
    def _session_dir() -> Path:
        config = Path(
            os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        )
        d = config / "hashaxe" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _path_for(self, name: str) -> Path:
        return self._session_dir() / f"{name}.session"

    # ── Save / load ───────────────────────────────────────────────────────────

    def save(self, name: str) -> Path:
        """Persist session to disk in an atomic manner.  Returns path written."""
        self.last_updated = time.time()
        self.elapsed     += time.time() - self.start_time
        self.start_time   = time.time()

        path = self._path_for(name)
        temp_path = path.with_suffix(".tmp")
        try:
            temp_path.write_text(json.dumps(asdict(self), indent=2))
            os.replace(temp_path, path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
        return path

    @classmethod
    def load(cls, name: str) -> Session:
        """Load a session from disk.  Raises FileNotFoundError if not found."""
        d    = cls._session_dir()
        path = d / f"{name}.session"
        if not path.exists():
            raise FileNotFoundError(
                f"Session '{name}' not found.\n"
                f"  Looked in: {path}\n"
                f"  Run 'hashaxe --list-sessions' to see saved sessions."
            )
        data = json.loads(path.read_text())
        session = cls(**data)
        # BUG-1 fix: reset start_time so elapsed doesn't double-count
        session.start_time = time.time()
        return session

    def delete(self, name: str) -> None:
        """Remove a session file."""
        p = self._path_for(name)
        if p.exists():
            p.unlink()

    @classmethod
    def list_sessions(cls) -> list[dict]:
        """Return metadata for all saved sessions."""
        d = cls._session_dir()
        sessions = []
        for f in sorted(d.glob("*.session")):
            try:
                data = json.loads(f.read_text())
                sessions.append({
                    "name":        f.stem,
                    "key_path":    data.get("key_path", "?"),
                    "words_tried": data.get("words_tried", 0),
                    "elapsed":     data.get("elapsed", 0),
                    "mode":        data.get("mode", "?"),
                    "last_updated":data.get("last_updated", 0),
                })
            except Exception:
                continue
        return sessions

    # ── Key integrity check ───────────────────────────────────────────────────

    @staticmethod
    def hash_key_file(path: str | None = None, raw_hash: str | None = None) -> str:
        """Compute SHA256 of key file or raw hash. Used to detect if target changed."""
        if path:
            data = Path(path).read_bytes()
        elif raw_hash:
            data = raw_hash.encode("utf-8")
        else:
            return "sha256:empty"
        return "sha256:" + hashlib.sha256(data).hexdigest()[:16]

    def is_stale(self) -> bool:
        """True if the key file has changed since this session was created."""
        if self.key_path:
            if not Path(self.key_path).exists():
                return True
            return self.hash_key_file(path=self.key_path) != self.key_hash
        return False

    # ── Progress update ───────────────────────────────────────────────────────

    def update(self, bytes_done: int, words_tried: int) -> None:
        """Update progress counters (call periodically during cracking)."""
        self.bytes_done  = bytes_done
        self.words_tried = words_tried

    # ── Display ───────────────────────────────────────────────────────────────

    def progress_summary(self) -> str:
        total_elapsed = self.elapsed + (time.time() - self.start_time)
        speed = self.words_tried / total_elapsed if total_elapsed > 0 else 0
        return (
            f"Session   : {self.session_id}\n"
            f"Key       : {self.key_path}\n"
            f"Mode      : {self.mode}"
            f"{'  +rules' if self.use_rules else ''}"
            f"{'  mask=' + (self.mask or '') if self.mask else ''}\n"
            f"Tried     : {self.words_tried:,} candidates\n"
            f"Elapsed   : {total_elapsed:.1f}s\n"
            f"Avg speed : {speed:.1f} pw/s"
        )


# ── Session name from key path ────────────────────────────────────────────────

def session_name_for(key_path: str | None, wordlist: str) -> str:
    """
    Derive a deterministic session name from the key + wordlist paths.
    This means re-running the same command auto-resumes the same session.
    """
    key_str = key_path if key_path else "inline_hash"
    combined = f"{key_str}::{wordlist}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]
