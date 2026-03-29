# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/hash_scrypt.py
#  Standalone scrypt hash format handler for $scrypt$ and $7$ formats.
#  Memory-hard KDF using built-in hashlib.scrypt (Python 3.6+).
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
Standalone scrypt hash format handler.

Format: $scrypt$ln=N,r=R,p=P$salt_b64$hash_b64
Also supports: $7$ format from some systems.

Dependencies:
  - ``hashlib.scrypt`` (built-in, Python 3.6+)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from pathlib import Path
from typing import Optional

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# $scrypt$ln=N,r=R,p=P$salt$hash
_SCRYPT_RE = re.compile(
    r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$"
)

# SCRYPT:N:r:p:salt_b64:hash_b64   (Hashcat mode 8900)
_SCRYPT_HASHCAT_RE = re.compile(
    r"^SCRYPT:(\d+):(\d+):(\d+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$",
    re.IGNORECASE,
)


class ScryptFormat(BaseFormat):
    """Handler for standalone scrypt password hashes."""

    format_id   = "hash.scrypt"
    format_name = "scrypt"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _SCRYPT_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": "scrypt hash ($scrypt$ format)"},
            )
        if _SCRYPT_HASHCAT_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": "scrypt hash (SCRYPT: hashcat format)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        # Try $scrypt$ln= format first
        m = _SCRYPT_RE.match(text)
        if m:
            ln = int(m.group(1))
            r = int(m.group(2))
            p = int(m.group(3))
            salt = base64.b64decode(m.group(4))
            target_hash = base64.b64decode(m.group(5))
            n = 2 ** ln  # scrypt N parameter from log2
        else:
            # Try SCRYPT:N:r:p:salt:hash (hashcat) format
            m = _SCRYPT_HASHCAT_RE.match(text)
            if not m:
                raise ValueError(f"Invalid scrypt hash format: {text[:50]}")
            n = int(m.group(1))   # N is literal, not log2
            r = int(m.group(2))
            p = int(m.group(3))
            salt = base64.b64decode(m.group(4))
            target_hash = base64.b64decode(m.group(5))

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"scrypt (N={n}, r={r}, p={p})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.EXTREME,
            format_data={
                "n": n,
                "r": r,
                "p": p,
                "salt": salt,
                "target_hash_bytes": target_hash,
                "target_hash": text,
                "dklen": len(target_hash),
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Verify using hashlib.scrypt (built-in)."""
        try:
            n = target.format_data["n"]
            r = target.format_data["r"]
            p = target.format_data["p"]
            salt = target.format_data["salt"]
            expected = target.format_data["target_hash_bytes"]
            dklen = target.format_data.get("dklen", 32)

            derived = hashlib.scrypt(
                password, salt=salt, n=n, r=r, p=p, dklen=dklen
            )
            return derived == expected
        except (ValueError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.EXTREME

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "scrypt",
            "N": str(target.format_data.get("n", 0)),
            "r": str(target.format_data.get("r", 0)),
            "p": str(target.format_data.get("p", 0)),
            "Difficulty": "EXTREME (memory-hard, single-digit pw/s)",
        }


_registry = FormatRegistry()
_registry.register(ScryptFormat())
