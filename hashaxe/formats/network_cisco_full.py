# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/network_cisco_full.py
#  Cisco IOS/ASA password type handler for Types 0-9 from running configs.
#  Supports MD5, PBKDF2-SHA256, and scrypt-based Cisco password formats.
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
hashaxe.formats.network_cisco_full — Cisco IOS/ASA password type handler.

Supports the full Cisco password ecosystem found in running configs:
  - Type 0: Plaintext (no cracking needed)
  - Type 5: MD5-based ($1$ crypt) → hashcat -m 500
  - Type 7: Vigenère cipher (reversible, no cracking) → hashcat -m 500
  - Type 8: PBKDF2-HMAC-SHA256 ($8$) → hashcat -m 9200
  - Type 9: scrypt ($9$) → hashcat -m 9300
  - Type 4: SHA-256 (deprecated, insecure) → hashcat -m 5700

Input from: show running-config, TFTP backup, startup-config files
Source: Cisco IOS, IOS-XE, NX-OS, ASA
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from pathlib import Path

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────────────

# Cisco Type 5: $1$salt$hash (MD5 crypt)
_CISCO5_RE = re.compile(r"^\$1\$([./A-Za-z0-9]{1,8})\$([./A-Za-z0-9]{22})$")

# Cisco Type 7: reversible Vigenère (2-char hex prefix + hex encoded)
_CISCO7_RE = re.compile(r"^[0-9]{2}[0-9A-Fa-f]{4,}$")

# Cisco Type 8: $8$salt$hash (PBKDF2-HMAC-SHA256)
# Salt and hash lengths vary in real configs (14-16 salt, 43-44 hash)
_CISCO8_RE = re.compile(r"^\$8\$([A-Za-z0-9./]+)\$([A-Za-z0-9./]+)$")

# Cisco Type 9: $9$salt$hash (scrypt)
# Salt and hash lengths vary in real configs (14-16 salt, 43-44 hash)
_CISCO9_RE = re.compile(r"^\$9\$([A-Za-z0-9./]+)\$([A-Za-z0-9./]+)$")

# Cisco Type 4: plain SHA-256 (deprecated)
_CISCO4_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Vigenère key for Type 7 decoding
_TYPE7_KEY = [
    0x64,
    0x73,
    0x66,
    0x64,
    0x3B,
    0x6B,
    0x66,
    0x6F,
    0x41,
    0x2C,
    0x2E,
    0x69,
    0x79,
    0x65,
    0x77,
    0x72,
    0x6B,
    0x6C,
    0x64,
    0x4A,
    0x4B,
    0x44,
    0x48,
    0x53,
    0x55,
    0x42,
    0x73,
    0x67,
    0x76,
    0x63,
    0x61,
    0x36,
    0x39,
    0x38,
    0x33,
    0x34,
    0x6E,
    0x63,
    0x78,
]


def decode_type7(encoded: str) -> str:
    """Decode a Cisco Type 7 password — this is NOT cracking, it's reversible."""
    try:
        seed = int(encoded[:2])
        decoded = ""
        for i in range(2, len(encoded), 2):
            val = int(encoded[i : i + 2], 16)
            decoded += chr(val ^ _TYPE7_KEY[(seed + (i - 2) // 2) % len(_TYPE7_KEY)])
        return decoded
    except (ValueError, IndexError):
        return ""


class CiscoType5Format(BaseFormat):
    """Cisco Type 5 — MD5 crypt ($1$salt$hash).

    Same as standard Unix md5crypt. Used in older IOS versions.
    """

    format_id = "network.cisco_type5"
    format_name = "Cisco Type 5 (MD5 crypt)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _CISCO5_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.9,
                metadata={"description": "Cisco Type 5 (MD5 crypt)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _CISCO5_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Cisco Type 5 format: {text[:80]}")

        salt = m.group(1)
        hash_val = m.group(2)

        return FormatTarget(
            format_id=self.format_id,
            display_name="Cisco Type 5 (MD5 Crypt)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.MEDIUM,
            format_data={
                "target_hash": text,
                "type": 5,
                "salt": salt,
                "hash": hash_val,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """MD5 crypt verification — delegates to crypt library if available."""
        try:
            import crypt as _crypt

            full = target.format_data["full"]
            salt = target.format_data["salt"]
            computed = _crypt.crypt(password.decode("utf-8", "replace"), f"$1${salt}$")
            return hmac.compare_digest(computed, full)
        except (ImportError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Cisco Type 5 (MD5 crypt, $1$)",
            "Hashcat Mode": "500",
            "Source": "Cisco IOS running-config",
            "Difficulty": "FAST (md5crypt — millions pw/s GPU)",
        }


class CiscoType8Format(BaseFormat):
    """Cisco Type 8 — PBKDF2-HMAC-SHA256 ($8$salt$hash).

    Modern Cisco IOS-XE. 20000 iterations, significantly slower.
    """

    format_id = "network.cisco_type8"
    format_name = "Cisco Type 8 (PBKDF2-SHA256)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _CISCO8_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "Cisco Type 8 (PBKDF2-HMAC-SHA256)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _CISCO8_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Cisco Type 8 format: {text[:80]}")

        salt = m.group(1)
        hash_val = m.group(2)

        return FormatTarget(
            format_id=self.format_id,
            display_name="Cisco Type 8 (PBKDF2)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={
                "target_hash": text,
                "type": 8,
                "salt": salt,
                "hash": hash_val,
                "full": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        try:
            from passlib.hash import cisco_type8

            pwd_str = password.decode("utf-8", "replace")
            full_hash = target.format_data["full"]
            return cisco_type8.verify(pwd_str, full_hash)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Cisco Type 8 (PBKDF2-HMAC-SHA256, 20000 iters)",
            "Hashcat Mode": "9200",
            "Source": "Cisco IOS-XE running-config",
            "Difficulty": "SLOW (PBKDF2 20000 iterations)",
        }


class CiscoType9Format(BaseFormat):
    """Cisco Type 9 — scrypt ($9$salt$hash).

    Strongest Cisco password type. Uses scrypt for extreme memory hardness.
    """

    format_id = "network.cisco_type9"
    format_name = "Cisco Type 9 (scrypt)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _CISCO9_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "Cisco Type 9 (scrypt)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _CISCO9_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Cisco Type 9 format: {text[:80]}")

        return FormatTarget(
            format_id=self.format_id,
            display_name="Cisco Type 9 (scrypt)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.EXTREME,
            format_data={
                "target_hash": text,
                "type": 9,
                "salt": m.group(1),
                "hash": m.group(2),
                "full": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        try:
            from passlib.hash import cisco_type9

            pwd_str = password.decode("utf-8", "replace")
            full_hash = target.format_data["full"]
            return cisco_type9.verify(pwd_str, full_hash)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.EXTREME

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Cisco Type 9 (scrypt N=16384)",
            "Hashcat Mode": "9300",
            "Source": "Cisco IOS-XE running-config",
            "Difficulty": "EXTREME (scrypt — memory-hard)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(CiscoType5Format())
_registry.register(CiscoType8Format())
_registry.register(CiscoType9Format())
