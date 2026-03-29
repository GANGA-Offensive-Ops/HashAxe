# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/archive_rar.py
#  RAR archive format handler for RAR3 and RAR5 encryption.
#  Supports AES-128/256 with PBKDF key derivation and header verification.
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
hashaxe.formats.archive_rar — RAR archive format handler.

Supports RAR3 (AES-128 + SHA-1 PBKDF) and RAR5 (AES-256 + PBKDF2-HMAC-SHA256).
RAR archives with encrypted headers require the password to even list contents.

Dependencies:
  - ``unrar`` / ``rarfile`` (optional) for extraction-based verification

Hashcat modes:
  - RAR3-hp: -m 12500 (headers encrypted)
  - RAR5:    -m 13000
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from pathlib import Path
from typing import Any

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
    import rarfile  # type: ignore
    _HAS_RARFILE = True
except ImportError:
    _HAS_RARFILE = False

# RAR magic bytes
_RAR_MAGIC_V1 = b"Rar!\x1a\x07\x00"     # RAR 1.5–4.x
_RAR_MAGIC_V5 = b"Rar!\x1a\x07\x01\x00"  # RAR 5.0+


def _detect_rar_encryption(data: bytes) -> dict[str, Any]:
    """Detect RAR version and encryption status from raw bytes."""
    result: dict[str, Any] = {
        "encrypted": False,
        "version": "unknown",
        "headers_encrypted": False,
    }

    if data[:7] == _RAR_MAGIC_V1:
        result["version"] = "RAR3/4"
        # Check for encryption flag in archive flags (byte 10, bit 2)
        if len(data) > 12:
            flags = int.from_bytes(data[10:12], "little")
            if flags & 0x0080:  # HEAD_ENCRYPTED flag
                result["encrypted"] = True
                result["headers_encrypted"] = True
            elif flags & 0x0004:  # Solid archive may have encrypted files
                result["encrypted"] = True
    elif data[:8] == _RAR_MAGIC_V5:
        result["version"] = "RAR5"
        # RAR5 uses a different header structure
        # Encrypted archives have an encryption header after the main header
        if b"\x04\x03" in data[:256]:  # Encryption record type
            result["encrypted"] = True
            result["headers_encrypted"] = True

    # Fallback: try with rarfile if available
    if _HAS_RARFILE and not result["encrypted"]:
        from io import BytesIO
        try:
            rf = rarfile.RarFile(BytesIO(data))
            if rf.needs_password():
                result["encrypted"] = True
            rf.close()
        except rarfile.Error as e:
            log.debug("rarfile extraction check failed (likely invalid structure): %s", e)
        except Exception as e:
            log.debug("Unexpected error during rarfile encryption check: %s", e)

    return result


class RARFormat(BaseFormat):
    """Handler for RAR3/4 and RAR5 encrypted archives.

    RAR3: AES-128 with SHA-1 based key derivation (262144 iterations)
    RAR5: AES-256 with PBKDF2-HMAC-SHA256 (configurable iterations)
    """

    format_id = "archive.rar"
    format_name = "RAR Archive (AES-128/256)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        is_rar = data[:7] == _RAR_MAGIC_V1 or data[:8] == _RAR_MAGIC_V5
        if not is_rar:
            # Also check by extension
            if path and path.suffix.lower() == ".rar":
                return FormatMatch(
                    format_id=self.format_id,
                    handler=self,
                    confidence=0.5,
                    metadata={"description": "RAR file (by extension)"},
                )
            return None

        meta = _detect_rar_encryption(data)
        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": f"{meta['version']} archive (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={
                "description": (
                    f"Encrypted {meta['version']} archive"
                    f"{' (headers encrypted)' if meta['headers_encrypted'] else ''}"
                ),
            },
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        meta = _detect_rar_encryption(data)

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name=f"{meta['version']} (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        diff = FormatDifficulty.SLOW if meta["version"] == "RAR5" else FormatDifficulty.MEDIUM

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"{meta['version']} (encrypted)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=diff,
            format_data={
                **meta,
                "raw_data": data,
                "file_path": str(path) if path else None,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Try to extract/test the archive with the given password."""
        if not _HAS_RARFILE:
            log.debug("rarfile not installed — RAR cracking unavailable")
            return False
        return self._verify_rarfile(target, password)

    def _verify_rarfile(self, target: FormatTarget, password: bytes) -> bool:
        from io import BytesIO
        data = target.format_data.get("raw_data")
        if not data:
            return False
        try:
            rf = rarfile.RarFile(BytesIO(data))
            rf.setpassword(password.decode("utf-8", errors="replace"))
            # Try to read the first file
            for info in rf.infolist():
                rf.read(info)
                break
            rf.close()
            return True
        except (rarfile.BadRarFile, RuntimeError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        version = target.format_data.get("version", "unknown")
        mode = "12500" if "3" in version or "4" in version else "13000"
        return {
            "Format": "RAR Archive",
            "Version": version,
            "Headers Encrypted": str(target.format_data.get("headers_encrypted", False)),
            "Hashcat Mode": mode,
            "rarfile": "Yes" if _HAS_RARFILE else "No (install rarfile)",
            "Difficulty": "MEDIUM-SLOW (AES + PBKDF)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(RARFormat())
