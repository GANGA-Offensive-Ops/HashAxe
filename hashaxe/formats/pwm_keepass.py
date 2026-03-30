# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/pwm_keepass.py
#  KeePass database (.kdbx) format handler for password manager cracking.
#  Supports KDBX v3 (AES-256+SHA-256) and v4 (AES-256+Argon2d/Argon2id).
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
hashaxe.formats.pwm_keepass — KeePass database (.kdbx) format handler.

Supports:
  - KeePass 2.x KDBX v3 (AES-256 + SHA-256 key derivation)
  - KeePass 2.x KDBX v4 (AES-256 + Argon2d/Argon2id key derivation)

The KDBX format stores all passwords in a single encrypted database file.
Cracking requires brute-forcing the master password.

Dependencies:
  - ``pykeepass`` (optional) for full libkeepass-based cracking
  - Falls back to header-only detection if pykeepass unavailable

Hashcat modes:
  - KDBX v3 (AES-KDF): -m 13400
  - KDBX v4 (Argon2):  -m 13400 (same mode, different variant)

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

import hashlib
import logging
import struct
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
    import pykeepass  # type: ignore

    _HAS_PYKEEPASS = True
except ImportError:
    _HAS_PYKEEPASS = False

# KDBX magic bytes: 0x9AA2D903 0xB54BFB67
_KDBX_MAGIC_1 = b"\x03\xd9\xa2\x9a"  # Signature 1 (LE)
_KDBX_MAGIC_2 = b"\x67\xfb\x4b\xb5"  # Signature 2 (LE)


def _detect_kdbx_version(data: bytes) -> dict[str, Any]:
    """Detect KDBX version and cipher info from header bytes."""
    result: dict[str, Any] = {
        "is_kdbx": False,
        "version_major": 0,
        "version_minor": 0,
        "kdf": "unknown",
    }

    if len(data) < 12:
        return result

    sig1 = data[0:4]
    sig2 = data[4:8]

    if sig1 == _KDBX_MAGIC_1 and sig2 == _KDBX_MAGIC_2:
        result["is_kdbx"] = True
        result["version_minor"] = struct.unpack_from("<H", data, 8)[0]
        result["version_major"] = struct.unpack_from("<H", data, 10)[0]

        if result["version_major"] >= 4:
            result["kdf"] = "Argon2"
        else:
            result["kdf"] = "AES-KDF"

    return result


class KeePassFormat(BaseFormat):
    """Handler for KeePass KDBX v3/v4 databases.

    KDBX v3: AES-256 + AES-KDF (default 6000 rounds)
    KDBX v4: AES-256 or ChaCha20 + Argon2d/id (configurable)
    """

    format_id = "pwm.keepass"
    format_name = "KeePass KDBX Database"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        # Check magic bytes
        if len(data) >= 8 and data[0:4] == _KDBX_MAGIC_1 and data[4:8] == _KDBX_MAGIC_2:
            meta = _detect_kdbx_version(data)
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={
                    "description": (
                        f"KeePass KDBX v{meta['version_major']}.{meta['version_minor']} "
                        f"({meta['kdf']} KDF)"
                    ),
                },
            )

        # Extension-based fallback
        if path and path.suffix.lower() in (".kdbx", ".kdb"):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.7,
                metadata={"description": "KeePass database (by extension)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        if not _HAS_PYKEEPASS:
            raise NotImplementedError("Missing dependency: pykeepass is required to crack KeePass databases.")
        meta = _detect_kdbx_version(data)

        if not meta["is_kdbx"]:
            raise ValueError("Not a valid KDBX file")

        kdf = meta["kdf"]
        diff = FormatDifficulty.EXTREME if kdf == "Argon2" else FormatDifficulty.SLOW

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"KeePass v{meta['version_major']} ({kdf})",
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
        if not _HAS_PYKEEPASS:
            log.debug("pykeepass not installed — KeePass cracking unavailable")
            return False
        return self._verify_pykeepass(target, password)

    def _verify_pykeepass(self, target: FormatTarget, password: bytes) -> bool:
        from io import BytesIO

        data = target.format_data.get("raw_data")
        fp = target.format_data.get("file_path")
        try:
            if fp:
                pykeepass.PyKeePass(fp, password=password.decode("utf-8", "replace"))
            elif data:
                # pykeepass can read from file path only
                import tempfile

                with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=True) as tmp:
                    tmp.write(data)
                    tmp.flush()
                    pykeepass.PyKeePass(tmp.name, password=password.decode("utf-8", "replace"))
            return True
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        kdf = target.format_data.get("kdf", "unknown")
        ver = target.format_data.get("version_major", 0)
        return {
            "Format": "KeePass KDBX",
            "Version": f"v{ver}",
            "KDF": kdf,
            "Hashcat Mode": "13400",
            "pykeepass": "Yes" if _HAS_PYKEEPASS else "No (install pykeepass)",
            "Difficulty": "EXTREME" if kdf == "Argon2" else "SLOW",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(KeePassFormat())
