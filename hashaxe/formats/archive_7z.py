# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/archive_7z.py
#  7-Zip archive format handler for AES-256 + SHA-256 stretched encryption.
#  Supports encrypted 7z archives with password verification via py7zr.
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
7-Zip archive format handler — AES-256 + SHA-256 stretch.

Dependencies:
  - ``py7zr`` (optional) for 7z extraction
"""
from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path
from typing import Any, Optional

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# ── Optional dependency ───────────────────────────────────────────────────────
try:
    import py7zr  # type: ignore

    _HAS_PY7ZR = True
except ImportError:
    _HAS_PY7ZR = False

# 7z magic bytes: 7z\xbc\xaf\x27\x1c
_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"


def _detect_7z_encryption(data: bytes) -> dict[str, Any]:
    """Detect whether a 7z archive is encrypted.

    Returns dict with:
      encrypted: bool
      method: '7zaes256' or 'none'
      file_count: number of members (if detectable)
    """
    result: dict[str, Any] = {
        "encrypted": False,
        "method": "none",
        "file_count": 0,
    }

    if not _HAS_PY7ZR:
        # Without py7zr, we can only confirm it's a 7z by magic
        if data[:6] == _7Z_MAGIC:
            result["encrypted"] = True  # Assume encrypted (safer default)
            result["method"] = "7zaes256"
        return result

    try:
        with py7zr.SevenZipFile(BytesIO(data), mode="r") as szf:
            result["file_count"] = len(szf.getnames())
            # py7zr raises PasswordRequired on list() if encrypted
            # If we get here without error, it's not password-protected
            result["encrypted"] = False
            result["method"] = "none"
    except py7zr.exceptions.PasswordRequired:
        result["encrypted"] = True
        result["method"] = "7zaes256"
    except py7zr.exceptions.Bad7zFile as e:
        log.debug("Bad 7z file structure detected in py7zr: %s", e)
    except Exception as e:
        log.debug("Unexpected error during 7z encryption check: %s", e)
        # If we can't determine, fall back to header-based detection
        if data[:6] == _7Z_MAGIC:
            result["encrypted"] = True
            result["method"] = "7zaes256"

    return result


class SevenZipFormat(BaseFormat):
    """Handler for password-protected 7-Zip archives.

    7z uses AES-256 + SHA-256 key stretching (2^19 iterations default).
    """

    format_id = "archive.7z"
    format_name = "7-Zip Archive (AES-256)"

    # ── Identification ────────────────────────────────────────────────────────

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Detect 7z archive by magic bytes."""
        if len(data) < 6:
            return None

        if data[:6] != _7Z_MAGIC:
            return None

        meta = _detect_7z_encryption(data)
        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": "7-Zip archive (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={"description": "Encrypted 7-Zip archive (AES-256)"},
        )

    # ── Parsing ───────────────────────────────────────────────────────────────

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        """Parse 7z archive and extract encryption metadata."""
        meta = _detect_7z_encryption(data)

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name="7-Zip archive (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        # Try to get the hash for Hashcat using 7z2john
        target_hash = ""
        if path:
            import subprocess

            try:
                res = subprocess.run(
                    ["/usr/bin/7z2john", str(path)], capture_output=True, text=True, timeout=5
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if ":$7z$" in line:
                            target_hash = line.split(":", 1)[1].strip()
                            break
                        elif line.startswith("$7z$"):
                            target_hash = line.strip()
                            break
            except Exception as e:
                log.debug("7z2john extraction failed: %s", e)

        return FormatTarget(
            format_id=self.format_id,
            display_name="7-Zip (AES-256)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,  # AES-256 + SHA-256 2^19
            format_data={
                **meta,
                "raw_data": data,
                "file_path": str(path) if path else None,
                "target_hash": target_hash,
            },
        )

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Try to open the 7z archive with the given password."""
        if not _HAS_PY7ZR:
            log.warning("py7zr not installed — 7z cracking is unavailable")
            return False
        return self._verify_py7zr(target, password)

    def _verify_py7zr(self, target: FormatTarget, password: bytes) -> bool:
        """Verify using py7zr."""
        data = target.format_data.get("raw_data")
        if not data:
            return False
        try:
            pw_str = password.decode("utf-8", errors="replace")
            with py7zr.SevenZipFile(BytesIO(data), mode="r", password=pw_str) as szf:
                # Try to read one file to confirm the password works
                result = szf.read()
                if result is not None:
                    return True
                return False
        except py7zr.exceptions.PasswordRequired:
            return False
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """Full verification — same as fast path for 7z."""
        return self.verify(target, password)

    # ── Metadata ──────────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        count = target.format_data.get("file_count", 0)
        return {
            "Format": "7-Zip Archive",
            "Encryption": "AES-256 + SHA-256 stretch",
            "Files": str(count),
            "py7zr": "Yes" if _HAS_PY7ZR else "No (install py7zr)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(SevenZipFormat())
