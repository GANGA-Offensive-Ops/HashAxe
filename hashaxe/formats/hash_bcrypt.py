# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/hash_bcrypt.py
#  bcrypt hash format handler for $2a$, $2b$, $2y$ variants.
#  Blowfish-based CPU-bound KDF with configurable cost factor for password hashing.
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
bcrypt hash format handler — $2a$, $2b$, $2y$ variants.

bcrypt uses Blowfish in a CPU-bound key schedule with configurable cost factor.
Typical speeds: ~300 pw/s per core at cost=12 (default), dropping exponentially.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# ── Try to import bcrypt library ──────────────────────────────────────────────

_HAS_BCRYPT = False
try:
    import bcrypt as _bcrypt_mod
    _HAS_BCRYPT = True
except ImportError:
    pass

# ── Regex ─────────────────────────────────────────────────────────────────────

_BCRYPT_RE = re.compile(r'^\$2([aby])\$(\d{2})\$([./A-Za-z0-9]{53})$')


class BcryptFormat(BaseFormat):
    """Handler for bcrypt hashes ($2a$, $2b$, $2y$).

    Cost factor determines difficulty:
      cost=10: ~1,500 pw/s (MEDIUM)
      cost=12: ~300 pw/s   (HARD)
      cost=14: ~75 pw/s    (VERY HARD)
      cost=16: ~19 pw/s    (EXTREME)
    """

    format_id   = "hash.bcrypt"
    format_name = "bcrypt"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        # Extract from shadow line
        if ":" in text:
            parts = text.split(":")
            if len(parts) >= 2 and parts[1].startswith("$2"):
                text = parts[1]

        if _BCRYPT_RE.match(text):
            m = _BCRYPT_RE.match(text)
            cost = int(m.group(2)) if m else 12
            return FormatMatch(
                format_id="hash.bcrypt",
                handler=self,
                confidence=1.0,
                metadata={"description": f"bcrypt $2{m.group(1)}$ (cost={cost})"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        # Extract from shadow line
        if ":" in text:
            parts = text.split(":")
            if len(parts) >= 2 and parts[1].startswith("$2"):
                text = parts[1]

        m = _BCRYPT_RE.match(text)
        if not m:
            raise ValueError(f"Invalid bcrypt hash: {text[:30]}...")

        variant = m.group(1)
        cost = int(m.group(2))

        # Difficulty based on cost factor
        if cost >= 16:
            diff = FormatDifficulty.EXTREME
        elif cost >= 14:
            diff = FormatDifficulty.SLOW
        elif cost >= 12:
            diff = FormatDifficulty.SLOW
        elif cost >= 10:
            diff = FormatDifficulty.MEDIUM
        else:
            diff = FormatDifficulty.FAST

        return FormatTarget(
            format_id="hash.bcrypt",
            display_name=f"bcrypt $2{variant}$ (cost={cost})",
            source_path=str(path) if path else None,
            is_encrypted=True,
            difficulty=diff,
            format_data={
                "target_hash": text,
                "variant": variant,
                "cost": cost,
                "full_hash": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Verify using the bcrypt library."""
        if not _HAS_BCRYPT:
            log.error("bcrypt library not installed. Install: pip install bcrypt")
            return False

        full_hash = target.format_data["full_hash"]
        try:
            return _bcrypt_mod.checkpw(password, full_hash.encode("utf-8"))
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict:
        cost = target.format_data.get("cost", 12)
        variant = target.format_data.get("variant", "b")
        return {
            "Variant": f"$2{variant}$",
            "Cost": str(cost),
            "Hash": target.format_data.get("full_hash", "")[:30] + "...",
            "Difficulty": self.difficulty().name,
        }

# ── Auto-register ────────────────────────────────────────────────────────────
from hashaxe.formats._registry import FormatRegistry
_registry = FormatRegistry()
_registry.register(BcryptFormat())
