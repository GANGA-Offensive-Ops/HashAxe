# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/archive_zip.py
#  ZIP archive format handler for ZipCrypto and WinZip AES-128/192/256 encryption.
#  Supports legacy CRC32-based and modern PBKDF2-based encrypted ZIPs.
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
ZIP archive format handler — ZipCrypto and WinZip AES-256.

Supports:
  - ZipCrypto (legacy, fast, CRC32-based)
  - WinZip AES-128/192/256 (PBKDF2, slower)

Dependencies:
  - ``zipfile`` (built-in) for ZipCrypto
  - ``pyzipper`` (optional) for AES-encrypted ZIPs
"""
from __future__ import annotations

import logging
import struct
import zipfile
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
    import pyzipper  # type: ignore

    _HAS_PYZIPPER = True
except ImportError:
    _HAS_PYZIPPER = False


def _detect_zip_encryption(data: bytes) -> dict[str, Any]:
    """Analyse a ZIP buffer to determine encryption type and metadata.

    Returns dict with keys:
      encrypted: bool
      method: 'zipcrypto' | 'aes128' | 'aes192' | 'aes256' | 'unknown'
      first_file: name of first encrypted member
      crc32: expected CRC (for ZipCrypto fast-reject)
      file_count: total members
    """
    result: dict[str, Any] = {
        "encrypted": False,
        "method": "none",
        "first_file": "",
        "crc32": 0,
        "file_count": 0,
    }

    try:
        zf = zipfile.ZipFile(BytesIO(data))
    except (zipfile.BadZipFile, Exception):
        return result

    result["file_count"] = len(zf.infolist())

    for info in zf.infolist():
        if info.flag_bits & 0x1:  # bit 0 = encrypted
            result["encrypted"] = True
            result["first_file"] = info.filename
            result["crc32"] = info.CRC

            # Check for AES (compression method 99 = WinZip AES)
            if info.compress_type == 99:
                # AES extra field: 0x9901
                for extra in _parse_extra_fields(info.extra):
                    if extra[0] == 0x9901 and len(extra[1]) >= 7:
                        strength = extra[1][4]
                        if strength == 1:
                            result["method"] = "aes128"
                        elif strength == 2:
                            result["method"] = "aes192"
                        elif strength == 3:
                            result["method"] = "aes256"
                        else:
                            result["method"] = "aes_unknown"
                        break
                else:
                    result["method"] = "aes256"  # default assumption
            else:
                result["method"] = "zipcrypto"
            break

    zf.close()
    return result


def _parse_extra_fields(extra: bytes) -> list[tuple[int, bytes]]:
    """Parse ZIP extra field blocks."""
    fields: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(extra):
        header_id = struct.unpack("<H", extra[offset : offset + 2])[0]
        size = struct.unpack("<H", extra[offset + 2 : offset + 4])[0]
        if offset + 4 + size > len(extra):
            break
        fields.append((header_id, extra[offset + 4 : offset + 4 + size]))
        offset += 4 + size
    return fields


class ZipFormat(BaseFormat):
    """Handler for password-protected ZIP archives.

    Supports both ZipCrypto (legacy) and WinZip AES-256 encryption.
    """

    format_id = "archive.zip"
    format_name = "ZIP Archive (ZipCrypto / AES)"

    # ── Identification ────────────────────────────────────────────────────────

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Detect ZIP archives by magic bytes PK\\x03\\x04."""
        if len(data) < 4:
            return None

        # Primary ZIP magic: PK\x03\x04
        if data[:4] != b"PK\x03\x04" and data[:4] != b"PK\x05\x06":
            return None

        meta = _detect_zip_encryption(data)
        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,  # Low — it's a ZIP but not encrypted
                metadata={"description": "ZIP archive (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={
                "description": f"Encrypted ZIP ({meta['method']}) — {meta['file_count']} file(s)",
            },
        )

    # ── Parsing ───────────────────────────────────────────────────────────────

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        """Parse ZIP archive and extract encryption metadata."""
        meta = _detect_zip_encryption(data)

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name="ZIP archive (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        # Determine difficulty based on encryption method
        if meta["method"] == "zipcrypto":
            diff = FormatDifficulty.FAST
        elif meta["method"].startswith("aes"):
            diff = FormatDifficulty.MEDIUM  # PBKDF2 1000 iterations
        else:
            diff = FormatDifficulty.MEDIUM

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"ZIP ({meta['method']}) — {meta['first_file']}",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=diff,
            format_data={
                **meta,
                "raw_data": data,  # Store for extraction attempts
            },
        )

    # ── Verification (hot path) ───────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Try to extract the first encrypted file with the given password."""
        data = target.format_data.get("raw_data")
        first_file = target.format_data.get("first_file", "")
        method = target.format_data.get("method", "")

        if not data or not first_file:
            return False

        if method.startswith("aes") and _HAS_PYZIPPER:
            return self._verify_aes(data, first_file, password)
        else:
            return self._verify_zipcrypto(data, first_file, password)

    def _verify_zipcrypto(self, data: bytes, filename: str, password: bytes) -> bool:
        """Verify ZipCrypto password by attempting extraction."""
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                zf.read(filename, pwd=password)
                return True
        except (RuntimeError, zipfile.BadZipFile, Exception):
            return False

    def _verify_aes(self, data: bytes, filename: str, password: bytes) -> bool:
        """Verify AES-encrypted ZIP using pyzipper."""
        if not _HAS_PYZIPPER:
            return False
        try:
            with pyzipper.AESZipFile(BytesIO(data)) as zf:
                zf.read(filename, pwd=password)
                return True
        except (RuntimeError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """Full verification — same as fast path for ZIP."""
        return self.verify(target, password)

    # ── Metadata ──────────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        method = target.format_data.get("method", "unknown")
        count = target.format_data.get("file_count", 0)
        first = target.format_data.get("first_file", "")
        return {
            "Format": "ZIP Archive",
            "Encryption": method.upper(),
            "Files": str(count),
            "Target": first[:40] + ("..." if len(first) > 40 else ""),
            "AES Support": "Yes" if _HAS_PYZIPPER else "No (install pyzipper)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(ZipFormat())
