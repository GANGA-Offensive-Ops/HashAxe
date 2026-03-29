# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/ssh_ppk.py
#  PuTTY PPK private key format handler for PPK v2 and PPK v3 (Argon2id).
#  Only tool that cracks PPK v3 Argon2id KDF — Hashcat/John cannot.
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
hashaxe.formats.ssh_ppk — Format handler for PuTTY PPK private keys.

Handles:
  • PPK v2  — HMAC-SHA1, AES-256-CBC, salted MD5 KDF
  • PPK v3  — HMAC-SHA256, AES-256-CBC, Argon2id KDF

Uses the existing ``hashaxe.parser`` and ``hashaxe.engine`` modules
internally via composition — no code duplication.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from hashaxe.engine import try_passphrase, try_passphrase_full
from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)
from hashaxe.parser import (
    KeyFormat,
    ParsedKey,
    _parse_ppk_v2,
    _parse_ppk_v3,
)

logger = logging.getLogger(__name__)

# ── Magic bytes for identification ────────────────────────────────────────────
_PPK_V2_MAGIC = b"PuTTY-User-Key-File-2:"
_PPK_V3_MAGIC = b"PuTTY-User-Key-File-3:"


class PPKFormat(BaseFormat):
    """
    Format handler for PuTTY PPK private key files (v2 and v3).

    Identification:  Matches on PPK header magic bytes with confidence 1.0.
    Parsing:         Delegates to ``hashaxe.parser`` internal PPK functions.
    Verification:    Delegates to ``hashaxe.engine.try_passphrase()`` (MAC check)
                     and ``try_passphrase_full()``.
    """

    format_id = "ssh.ppk"
    format_name = "PuTTY PPK Private Key"

    # ── Identification ────────────────────────────────────────────────────

    def can_handle(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatMatch | None:
        """
        Detect PuTTY PPK keys by header magic bytes.

        PPK files start with ``PuTTY-User-Key-File-2:`` or
        ``PuTTY-User-Key-File-3:`` at the very beginning of the file.
        """
        # PPK headers are at the start of the file
        if data.lstrip().startswith(_PPK_V3_MAGIC):
            return FormatMatch(
                format_id=self.format_id,
                confidence=1.0,
                handler=self,
                metadata={"version": "3", "kdf": "argon2id"},
            )

        if data.lstrip().startswith(_PPK_V2_MAGIC):
            return FormatMatch(
                format_id=self.format_id,
                confidence=1.0,
                handler=self,
                metadata={"version": "2", "kdf": "md5"},
            )

        return None

    # ── Parsing ───────────────────────────────────────────────────────────

    def parse(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatTarget:
        """
        Parse a PuTTY PPK key file into a FormatTarget.

        PPK v3 uses Argon2id KDF (extremely slow, memory-hard = EXTREME).
        PPK v2 uses MD5-based KDF (fast, but still requires MAC check = MEDIUM).
        """
        # Normalise line endings
        raw = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

        stripped = raw.lstrip()
        if stripped.startswith(_PPK_V3_MAGIC):
            pk = _parse_ppk_v3(raw)
            version = "3"
            difficulty = FormatDifficulty.EXTREME  # Argon2id
        elif stripped.startswith(_PPK_V2_MAGIC):
            pk = _parse_ppk_v2(raw)
            version = "2"
            difficulty = FormatDifficulty.MEDIUM  # MD5 + HMAC-SHA1
        else:
            raise ValueError("No PPK magic header found in data")

        # Build display name
        algo = pk.ppk_algorithm or "unknown"
        display_name = f"PuTTY PPK v{version} ({algo})"

        return FormatTarget(
            format_id=self.format_id,
            display_name=display_name,
            source_path=str(path) if path else "",
            is_encrypted=pk.is_encrypted,
            difficulty=difficulty,
            format_data={
                "version": version,
                "algorithm": algo,
                "encryption": pk.ppk_encryption,
                "kdf": pk.ppk_kdf,
                "comment": pk.ppk_comment,
            },
            _legacy_pk=pk,
        )

    # ── Verification ──────────────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """
        Fast-path PPK password check via MAC verification.

        PPK has no checkints shortcut — the MAC based check IS the
        fast path. Still delegates to ``engine.try_passphrase()``.
        """
        pk = target._legacy_pk
        if pk is None:
            return False
        return try_passphrase(pk, password)

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """
        Full confirmation for PPK keys.

        For PPK, the MAC verification is already definitive (no false
        positive window), so verify_full() calls the same path but is
        kept separate for API consistency.
        """
        pk = target._legacy_pk
        if pk is None:
            return False
        return try_passphrase_full(pk, password)

    # ── Metadata ──────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        # PPK v3 is Argon2id = extreme, v2 = medium
        # Return worst-case; per-target difficulty is in FormatTarget
        return FormatDifficulty.EXTREME

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        data = target.format_data
        result: dict[str, str] = {
            "Type": f"PPK v{data.get('version', '?')}",
            "Algorithm": data.get("algorithm", "unknown"),
            "Encryption": data.get("encryption", "none"),
            "KDF": data.get("kdf", "none"),
        }
        comment = data.get("comment", "")
        if comment:
            result["Comment"] = comment
        return result


# ── Auto-register on import ───────────────────────────────────────────────────
FormatRegistry().register(PPKFormat())
