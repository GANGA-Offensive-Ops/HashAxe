# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/database_mssql.py
#  MSSQL password format handler for SHA-512 salted hashes.
#  Handles MSSQL 2012+ format: 0x0200 + salt + SHA-512(password_utf16le + salt).
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
MSSQL password format handler — SHA-512 salted.

MSSQL 2012+ uses:
  0x0200 + salt(4 bytes) + SHA-512(password_utf16le + salt)
"""
from __future__ import annotations

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

# MSSQL 2012: 0x0200 + 8 hex salt + 128 hex SHA-512 = 142 chars
_MSSQL_RE = re.compile(r"^0x0200[0-9A-Fa-f]{136}$", re.IGNORECASE)


class MSSQLFormat(BaseFormat):
    """Handler for MSSQL 2012+ SHA-512 salted password hashes."""

    format_id = "database.mssql"
    format_name = "MSSQL 2012+ (SHA-512)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _MSSQL_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.90,
                metadata={"description": "MSSQL 2012+ SHA-512 salted hash"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        # Strip 0x0200 prefix
        hex_body = text[6:]
        salt_hex = hex_body[:8]
        hash_hex = hex_body[8:]

        return FormatTarget(
            format_id=self.format_id,
            display_name="MSSQL 2012+ SHA-512",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.FAST,
            format_data={
                "salt": bytes.fromhex(salt_hex),
                "target_hash": hash_hex.lower(),
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """SHA-512(UTF-16LE(password) + salt) == target_hash"""
        salt = target.format_data["salt"]
        pw_utf16 = password.decode("utf-8", errors="replace").encode("utf-16-le")
        h = hashlib.sha512(pw_utf16 + salt).hexdigest()
        return h == target.format_data["target_hash"]

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "SHA-512(UTF16LE(pass) + salt)",
            "Salt": target.format_data.get("salt", b"").hex()[:16] + "...",
            "Difficulty": "FAST (hundreds of thousands pw/s)",
        }


_registry = FormatRegistry()
_registry.register(MSSQLFormat())
