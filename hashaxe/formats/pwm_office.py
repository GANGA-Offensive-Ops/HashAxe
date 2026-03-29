# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/pwm_office.py
#  Microsoft Office document format handler for password-protected files.
#  Supports Office 97-2013+ with AES/RC4 encryption and varying PBKDF rounds.
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
hashaxe.formats.pwm_office — Microsoft Office document format handler.

Supports password-protected Office documents (.docx, .xlsx, .pptx, .doc, .xls):
  - Office 2007 (AES-128 + SHA1, 50000 rounds) → hashcat -m 9400
  - Office 2010 (AES-128 + SHA1, 100000 rounds) → hashcat -m 9500
  - Office 2013+ (AES-256 + SHA512, 100000 rounds) → hashcat -m 9600
  - Office 97-2003 (RC4 + MD5) → hashcat -m 9700/9800

Office 2007+ uses OOXML (ZIP container with encrypted streams).
Office 97-2003 uses OLE2 compound file format.

Dependencies:
  - ``msoffcrypto-tool`` (optional) for full verification
  - Falls back to header/magic detection if unavailable

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

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
    import msoffcrypto  # type: ignore

    _HAS_MSOFFCRYPTO = True
except ImportError:
    _HAS_MSOFFCRYPTO = False

# Magic bytes
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE2 (Office 97-2003)
_ZIP_MAGIC = b"PK\x03\x04"  # OOXML/ZIP (Office 2007+)

# Known OOXML encrypted content markers
_OOXML_ENCRYPTED_MARKERS = [
    b"EncryptedPackage",
    b"EncryptionInfo",
    b"StrongEncryptionDataSpace",
]


def _detect_office_encryption(data: bytes, path: Path | None = None) -> dict[str, Any]:
    """Detect Office document type and encryption."""
    result: dict[str, Any] = {
        "is_office": False,
        "encrypted": False,
        "version": "unknown",
        "encryption_type": "none",
    }

    if _HAS_MSOFFCRYPTO and data[:8] == _OLE2_MAGIC:
        from io import BytesIO

        try:
            msoff = msoffcrypto.OfficeFile(BytesIO(data))
            result["is_office"] = True
            result["encrypted"] = msoff.is_encrypted()
            if msoff.format == "ooxml":
                result["version"] = "2007+"
                result["encryption_type"] = "aes"
                # Refine version and type if possible by scanning raw data
                if (
                    b's\x00p\x00i\x00n\x00C\x00o\x00u\x00n\x00t\x00=\x00"\x001\x000\x000\x000\x000\x000'
                    in data
                ):
                    if b"S\x00H\x00A\x005\x001\x002" in data:
                        result["version"] = "2013+"
                        result["encryption_type"] = "aes-256-sha512"
                    else:
                        result["version"] = "2010"
                        result["encryption_type"] = "aes-128-sha1"
                elif (
                    b's\x00p\x00i\x00n\x00C\x00o\x00u\x00n\x00t\x00=\x00"\x005\x000\x000\x000\x00'
                    in data
                ):
                    result["version"] = "2007"
                    result["encryption_type"] = "aes-128-sha1"
            elif msoff.format == "office97":
                result["version"] = "97-2003"
                result["encryption_type"] = "rc4-md5"
            return result
        except Exception:
            pass

    ext = path.suffix.lower() if path else ""

    if data[:8] == _OLE2_MAGIC:
        result["is_office"] = True
        result["version"] = "97-2003"
        result["version"] = "97-2003"
        # Check for encryption markers in OLE2
        if (
            b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e" in data
            or b"EncryptedPackage" in data
        ):
            result["encrypted"] = True
            result["version"] = "2007+"
            result["encryption_type"] = "aes"
        elif (
            b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n\x00I\x00n\x00f\x00o" in data
            or b"EncryptionInfo" in data
        ):
            result["encrypted"] = True
            result["encryption_type"] = "rc4-md5"
        elif b"\x13\x00\x00\x00" in data[:256]:  # Office encryption flag
            result["encrypted"] = True
            result["encryption_type"] = "rc4-md5"

    elif data[:4] == _ZIP_MAGIC:
        # Could be OOXML — check for Office markers
        if any(marker in data for marker in _OOXML_ENCRYPTED_MARKERS):
            result["is_office"] = True
            result["encrypted"] = True

            # Determine version from EncryptionInfo
            if b"<keyEncryptors" in data or b"spinCount" in data:
                # Parse spinCount to determine version
                spin_match = re.search(rb'spinCount="(\d+)"', data)
                if spin_match:
                    spin = int(spin_match.group(1))
                    if spin >= 100000:
                        hash_match = re.search(rb'hashAlgorithm="(\w+)"', data)
                        if hash_match and b"SHA512" in hash_match.group(1).upper():
                            result["version"] = "2013+"
                            result["encryption_type"] = "aes-256-sha512"
                        else:
                            result["version"] = "2010"
                            result["encryption_type"] = "aes-128-sha1"
                    else:
                        result["version"] = "2007"
                        result["encryption_type"] = "aes-128-sha1"
                else:
                    result["version"] = "2007+"
                    result["encryption_type"] = "aes-128"
            else:
                result["version"] = "2007+"
                result["encryption_type"] = "aes"

        elif ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm"):
            result["is_office"] = True
            result["version"] = "2007+"
            # Not encrypted — just a regular OOXML

    elif ext in (".doc", ".xls", ".ppt"):
        result["is_office"] = True
        result["version"] = "97-2003"

    return result


class OfficeFormat(BaseFormat):
    """Handler for password-protected Microsoft Office documents.

    Supports Office 97-2003 (RC4) through Office 2019+ (AES-256).
    Uses msoffcrypto-tool for verification when available.
    """

    format_id = "pwm.office"
    format_name = "Microsoft Office (RC4/AES)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        meta = _detect_office_encryption(data, path)
        if not meta["is_office"]:
            return None

        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": f"Office {meta['version']} (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={
                "description": (
                    f"Encrypted Office {meta['version']} " f"({meta['encryption_type']})"
                ),
            },
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        meta = _detect_office_encryption(data, path)

        if not meta["is_office"]:
            raise ValueError("Not a valid Microsoft Office document")

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name=f"Office {meta['version']} (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        enc = meta["encryption_type"]
        if "sha512" in enc or "256" in enc:
            diff = FormatDifficulty.SLOW
        elif "sha1" in enc or "128" in enc:
            diff = FormatDifficulty.MEDIUM
        else:
            diff = FormatDifficulty.FAST  # RC4-MD5

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Office {meta['version']} ({enc})",
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
        if not _HAS_MSOFFCRYPTO:
            log.debug("msoffcrypto not installed — Office cracking unavailable")
            return False
        return self._verify_msoffcrypto(target, password)

    def _verify_msoffcrypto(self, target: FormatTarget, password: bytes) -> bool:
        from io import BytesIO

        data = target.format_data.get("raw_data")
        if not data:
            return False
        try:
            f = msoffcrypto.OfficeFile(BytesIO(data))
            f.load_key(password=password.decode("utf-8", "replace"))
            out = BytesIO()
            f.decrypt(out)
            return True
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        ver = target.format_data.get("version", "unknown")
        enc = target.format_data.get("encryption_type", "unknown")
        mode_map = {
            "rc4-md5": "9700/9800",
            "aes-128-sha1": "9400/9500",
            "aes-256-sha512": "9600",
        }
        mode = mode_map.get(enc, "9400-9600")
        return {
            "Format": "Microsoft Office",
            "Version": ver,
            "Encryption": enc.upper(),
            "Hashcat Mode": mode,
            "msoffcrypto": "Yes" if _HAS_MSOFFCRYPTO else "No (install msoffcrypto-tool)",
            "Difficulty": "SLOW" if "sha512" in enc else "MEDIUM",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(OfficeFormat())
