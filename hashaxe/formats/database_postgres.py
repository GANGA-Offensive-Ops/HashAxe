# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/database_postgres.py
#  PostgreSQL MD5 password format handler for MD5(password + username) hashes.
#  Handles the standard 'md5' + MD5 hash format from pg_shadow catalog.
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
PostgreSQL MD5 password format handler — MD5(password + username).

The PostgreSQL md5 hash is:
  'md5' + MD5(password + username)  (35 chars total)
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

# PostgreSQL MD5: md5 + 32 hex chars = 35 chars
_PG_RE = re.compile(r"^md5[0-9a-f]{32}$", re.IGNORECASE)


class PostgreSQLFormat(BaseFormat):
    """Handler for PostgreSQL MD5 password hashes.

    Algorithm: 'md5' + MD5(password + username)
    Requires username (stored in format_data or provided via --format-arg).
    """

    format_id = "hash.postgres"
    format_name = "PostgreSQL MD5"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        # Check for md5 + 32hex format
        if _PG_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.80,
                metadata={"description": "PostgreSQL MD5 hash (requires username)"},
            )

        # Also detect user:hash format from pg_shadow dumps
        if ":" in text:
            parts = text.split(":", 1)
            # pg_shadow standard user:md5hash
            if len(parts) == 2 and _PG_RE.match(parts[1].strip()):
                return FormatMatch(
                    format_id=self.format_id,
                    handler=self,
                    confidence=0.90,
                    metadata={"description": f"PostgreSQL MD5 hash (user: {parts[0]})"},
                )

            # hashcat format hash:user  (hashcat -m 12 uses hash:salt where salt=username)
            hash_part = parts[0].strip()
            if (
                len(parts) == 2
                and len(hash_part) == 32
                and re.match(r"^[0-9a-f]{32}$", hash_part, re.IGNORECASE)
            ):
                # 32hex:username is AMBIGUOUS between PostgreSQL and DCC1.
                # Use file path as disambiguation:
                #   - File contains "postgres"/"pg" → high confidence (0.92, beats DCC1's 0.88)
                #   - No path hint → low confidence (0.85, defers to DCC1's 0.88)
                # Users can always force with --format hash.postgres
                path_hint = False
                if path is not None:
                    fname = path.name.lower()
                    path_hint = "postgres" in fname or "pg_" in fname or "pg." in fname
                conf = 0.92 if path_hint else 0.85
                return FormatMatch(
                    format_id=self.format_id,
                    handler=self,
                    confidence=conf,
                    metadata={
                        "description": f"PostgreSQL MD5 hashcat format (user: {parts[1].strip()})"
                    },
                )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        username = "postgres"  # default
        target_hash = text

        # Handle user:hash format
        if ":" in text:
            parts = text.split(":", 1)
            # Check if it's user:md5hash
            if _PG_RE.match(parts[1].strip()):
                username = parts[0].strip()
                target_hash = parts[1].strip()
            # Else it's hash:user (hashcat format)
            elif len(parts[0].strip()) == 32 and re.match(
                r"^[0-9a-f]{32}$", parts[0].strip(), re.IGNORECASE
            ):
                target_hash = parts[0].strip()
                username = parts[1].strip()

        # Strip 'md5' prefix
        if target_hash.lower().startswith("md5"):
            target_hash = target_hash[3:]

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"PostgreSQL MD5 (user: {username})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={
                "target_hash": f"{target_hash.lower()}:{username}",
                "username": username,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """MD5(password + username) == target_hash"""
        username = target.format_data.get("username", "postgres")
        expected_hash = target.format_data["target_hash"].split(":")[0]
        combined = password + username.encode("utf-8")
        return hashlib.md5(combined, usedforsecurity=False).hexdigest() == expected_hash

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "MD5(pass + user)",
            "Username": target.format_data.get("username", "unknown"),
            "Hash": "md5" + target.format_data.get("target_hash", "")[:16] + "...",
            "Difficulty": "TRIVIAL (millions pw/s)",
        }


_registry = FormatRegistry()
_registry.register(PostgreSQLFormat())
