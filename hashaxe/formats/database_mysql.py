# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/database_mysql.py
#  MySQL native password format handler for SHA1(SHA1(password)) hashes.
#  Handles mysql_native_password format from mysql.user table and dumps.
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
MySQL native password format handler — SHA1(SHA1(password)).

The mysql_native_password hash is:
  *UPPERCASE_HEX(SHA1(SHA1(password)))

Stored in mysql.user table or in MySQL dumps.
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

# MySQL native password: *HEX (41 chars: * + 40 hex)
_MYSQL_RE = re.compile(r"^\*[0-9A-Fa-f]{40}$")


class MySQLFormat(BaseFormat):
    """Handler for MySQL mysql_native_password hashes.

    Algorithm: SHA1(SHA1(password))
    Format: *UPPERCASE_HEX_40
    """

    format_id   = "database.mysql"
    format_name = "MySQL native_password"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _MYSQL_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.85,
                metadata={"description": "MySQL native_password hash"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip().upper()
        # Remove leading * if present
        target_hash = text[1:] if text.startswith("*") else text
        return FormatTarget(
            format_id=self.format_id,
            display_name="MySQL native_password",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={"target_hash": target_hash.lower()},
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """SHA1(SHA1(password)) == target_hash"""
        h1 = hashlib.sha1(password, usedforsecurity=False).digest()
        h2 = hashlib.sha1(h1, usedforsecurity=False).hexdigest()
        return h2 == target.format_data["target_hash"]

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "SHA1(SHA1(pass))",
            "Hash": "*" + target.format_data.get("target_hash", "")[:16].upper() + "...",
            "Difficulty": "TRIVIAL (millions pw/s)",
        }


_registry = FormatRegistry()
_registry.register(MySQLFormat())
