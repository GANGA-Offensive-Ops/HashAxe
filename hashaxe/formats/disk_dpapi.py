# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/disk_dpapi.py
#  DPAPI masterkey handler for Windows Data Protection API credentials.
#  Cracks masterkeys protecting browser passwords, Credential Manager, RDP, WiFi.
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
hashaxe.formats.disk_dpapi — DPAPI masterkey handler.

Supports cracking DPAPI masterkeys used by Windows to protect:
  • Browser saved passwords (Chrome, Edge, Firefox)
  • Windows Credential Manager entries
  • RDP saved credentials
  • WiFi passwords
  • Certificate private keys

  • DPAPI masterkey v1 (local context)   → hashcat -m 15300
  • DPAPI masterkey v2 (AD domain ctx)   → hashcat -m 15900

Input format:
  $DPAPImk$<version>*<context>*<SID>*<cipher>*<rounds>*<hmac_hex>*<salt_hex>

Extraction: dpapimk2hashcat or manual from:
  %APPDATA%\\Microsoft\\Protect\\{SID}\\{GUID}

MITRE ATT&CK: T1555.003 (Credentials from Password Stores: Windows Credential Manager)

GANGA Offensive Ops · Hashaxe V1
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

# $DPAPImk$<version>*<context>*<SID>*<cipher_algo>*<hmac_algo>*<rounds>*
# <iv_hex>*<key_len>*<ciphertext_hex>
_DPAPIMK_RE = re.compile(
    r"^\$DPAPImk\$(\d)\*(\d)\*"  # version, context
    r"(S-1-[0-9\-]+)\*"  # SID
    r"(\w+)\*(\w+)\*"  # cipher_algo, hmac_algo
    r"(\d+)\*"  # rounds
    r"([a-fA-F0-9]+)\*"  # iv or salt hex
    r"(\d+)\*"  # key/output length
    r"([a-fA-F0-9]+)$"  # ciphertext/hmac hex
)

# Mid-format: $DPAPImk$ver*ctx*SID*cipher_hex*rounds*salt_hex*hmac_hex
_DPAPIMK_MID_RE = re.compile(
    r"^\$DPAPImk\$(\d)\*(\d)\*"  # version, context
    r"(S-1-[0-9\-]+)\*"  # SID
    r"([a-fA-F0-9]+)\*"  # cipher/key hex
    r"(\d+)\*"  # rounds
    r"([a-fA-F0-9]+)\*"  # salt hex
    r"([a-fA-F0-9]+)$"  # hmac hex
)

# Simplified format used by some tools
_DPAPIMK_SIMPLE_RE = re.compile(r"^\$DPAPImk\$(\d)\*(\d)\*([a-fA-F0-9]+)\*([a-fA-F0-9]+)$")


class DPAPIMasterkeyV1Format(BaseFormat):
    """DPAPI masterkey v1 — local context (hashcat -m 15300).

    Used when the masterkey is protected by the user's local password.
    PBKDF2 with SHA-1 HMAC, typically 4000 iterations.
    """

    format_id = "disk.dpapi_v1"
    format_name = "DPAPI Masterkey v1 (Local)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        m = _DPAPIMK_RE.match(text)
        if m and m.group(1) == "1":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "DPAPI Masterkey v1 (local context)"},
            )

        m_mid = _DPAPIMK_MID_RE.match(text)
        if m_mid and m_mid.group(1) == "1":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": "DPAPI Masterkey v1 (mid-format)"},
            )

        m2 = _DPAPIMK_SIMPLE_RE.match(text)
        if m2 and m2.group(1) == "1":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.9,
                metadata={"description": "DPAPI Masterkey v1 (simplified)"},
            )

        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        m = _DPAPIMK_RE.match(text)
        if m and m.group(1) == "1":
            sid = m.group(3)
            cipher_algo = m.group(4)
            hmac_algo = m.group(5)
            rounds = int(m.group(6))
            salt = bytes.fromhex(m.group(7))
            key_len = int(m.group(8))
            ciphertext = bytes.fromhex(m.group(9))

            return FormatTarget(
                format_id=self.format_id,
                display_name=f"DPAPI v1 ({sid})",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 1,
                    "context": int(m.group(2)),
                    "sid": sid,
                    "cipher_algo": cipher_algo,
                    "hmac_algo": hmac_algo,
                    "rounds": rounds,
                    "salt": salt,
                    "key_len": key_len,
                    "ciphertext": ciphertext,
                },
            )

        m2 = _DPAPIMK_MID_RE.match(text)
        if m2 and m2.group(1) == "1":
            sid = m2.group(3)
            rounds = int(m2.group(5))
            salt = bytes.fromhex(m2.group(6))
            ciphertext = bytes.fromhex(m2.group(4))
            hmac_data = bytes.fromhex(m2.group(7))

            return FormatTarget(
                format_id=self.format_id,
                display_name=f"DPAPI v1 ({sid})",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 1,
                    "context": int(m2.group(2)),
                    "sid": sid,
                    "cipher_algo": "des3",
                    "hmac_algo": "sha1",
                    "rounds": rounds,
                    "salt": salt,
                    "key_len": len(ciphertext),
                    "ciphertext": ciphertext,
                },
            )

        m3 = _DPAPIMK_SIMPLE_RE.match(text)
        if m3 and m3.group(1) == "1":
            salt = bytes.fromhex(m3.group(3))
            ciphertext = bytes.fromhex(m3.group(4))

            return FormatTarget(
                format_id=self.format_id,
                display_name="DPAPI v1 (simplified)",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 1,
                    "context": int(m3.group(2)),
                    "sid": "",
                    "cipher_algo": "des3",
                    "hmac_algo": "sha1",
                    "rounds": 4000,
                    "salt": salt,
                    "key_len": len(ciphertext),
                    "ciphertext": ciphertext,
                },
            )

        # Graceful fallback for malformed/partial extracts during info
        return FormatTarget(
            format_id=self.format_id,
            display_name="DPAPI v1 (unknown/partial)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={"version": 1, "error": "Malformed DPAPI format"},
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """DPAPI v1 verification via PBKDF2-HMAC-SHA1.

        1. Derive UTF-16LE password hash via SHA1
        2. PBKDF2(SHA1, derived_key, salt, rounds, dklen)
        3. HMAC-SHA1 comparison
        """
        salt = target.format_data["salt"]
        ciphertext = target.format_data["ciphertext"]
        rounds = target.format_data["rounds"]

        try:
            pw_sha1 = hashlib.sha1(
                password.decode("utf-8", "replace").encode("utf-16-le"),
                usedforsecurity=False,
            ).digest()

            derived = hashlib.pbkdf2_hmac("sha1", pw_sha1, salt, rounds, dklen=32)

            computed_hmac = hmac.new(derived, ciphertext[:-20], "sha1").digest()

            return hmac.compare_digest(computed_hmac, ciphertext[-20:])
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "DPAPI Masterkey v1 (SHA1 + PBKDF2)",
            "SID": target.format_data.get("sid", "unknown"),
            "Rounds": str(target.format_data.get("rounds", 4000)),
            "Hashcat Mode": "15300",
            "MITRE": "T1555.003",
            "Difficulty": "SLOW (PBKDF2 4000+ iterations)",
        }


class DPAPIMasterkeyV2Format(BaseFormat):
    """DPAPI masterkey v2 — AD domain context (hashcat -m 15900).

    Used when the masterkey is protected by the domain backup key.
    Uses PBKDF2 with SHA-512 HMAC, typically 8000 iterations.
    """

    format_id = "disk.dpapi_v2"
    format_name = "DPAPI Masterkey v2 (Domain)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        m = _DPAPIMK_RE.match(text)
        if m and m.group(1) == "2":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "DPAPI Masterkey v2 (AD domain)"},
            )

        m_mid = _DPAPIMK_MID_RE.match(text)
        if m_mid and m_mid.group(1) == "2":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": "DPAPI Masterkey v2 (mid-format)"},
            )

        m2 = _DPAPIMK_SIMPLE_RE.match(text)
        if m2 and m2.group(1) == "2":
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.9,
                metadata={"description": "DPAPI Masterkey v2 (simplified)"},
            )

        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        m = _DPAPIMK_RE.match(text)
        if m and m.group(1) == "2":
            sid = m.group(3)
            rounds = int(m.group(6))
            salt = bytes.fromhex(m.group(7))
            key_len = int(m.group(8))
            ciphertext = bytes.fromhex(m.group(9))

            return FormatTarget(
                format_id=self.format_id,
                display_name=f"DPAPI v2 ({sid})",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 2,
                    "sid": sid,
                    "rounds": rounds,
                    "salt": salt,
                    "key_len": key_len,
                    "ciphertext": ciphertext,
                },
            )

        m2 = _DPAPIMK_MID_RE.match(text)
        if m2 and m2.group(1) == "2":
            sid = m2.group(3)
            rounds = int(m2.group(5))
            salt = bytes.fromhex(m2.group(6))
            ciphertext = bytes.fromhex(m2.group(4))

            return FormatTarget(
                format_id=self.format_id,
                display_name=f"DPAPI v2 ({sid})",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 2,
                    "sid": sid,
                    "rounds": rounds,
                    "salt": salt,
                    "key_len": len(ciphertext),
                    "ciphertext": ciphertext,
                },
            )

        m3 = _DPAPIMK_SIMPLE_RE.match(text)
        if m3 and m3.group(1) == "2":
            salt = bytes.fromhex(m3.group(3))
            ciphertext = bytes.fromhex(m3.group(4))

            return FormatTarget(
                format_id=self.format_id,
                display_name="DPAPI v2 (simplified)",
                source_path=str(path) if path else "inline",
                is_encrypted=True,
                difficulty=FormatDifficulty.SLOW,
                format_data={
                    "version": 2,
                    "sid": "",
                    "rounds": 8000,
                    "salt": salt,
                    "key_len": len(ciphertext),
                    "ciphertext": ciphertext,
                },
            )

        # Graceful fallback for malformed/partial extracts during info
        return FormatTarget(
            format_id=self.format_id,
            display_name="DPAPI v2 (unknown/partial)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={"version": 2, "error": "Malformed DPAPI format"},
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """DPAPI v2: SHA-512 based PBKDF2 derivation."""
        salt = target.format_data["salt"]
        ciphertext = target.format_data["ciphertext"]
        rounds = target.format_data["rounds"]

        try:
            pw_sha512 = hashlib.sha512(
                password.decode("utf-8", "replace").encode("utf-16-le")
            ).digest()

            derived = hashlib.pbkdf2_hmac("sha512", pw_sha512, salt, rounds, dklen=64)

            computed_hmac = hmac.new(derived[:32], ciphertext[:-32], "sha512").digest()[:32]

            return hmac.compare_digest(computed_hmac, ciphertext[-32:])
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "DPAPI Masterkey v2 (SHA512 + PBKDF2)",
            "SID": target.format_data.get("sid", "unknown"),
            "Rounds": str(target.format_data.get("rounds", 8000)),
            "Hashcat Mode": "15900",
            "MITRE": "T1555.003",
            "Difficulty": "SLOW (PBKDF2-SHA512 8000+ iterations)",
        }


# ── Register ──────────────────────────────────────────────────────────────────

_registry = FormatRegistry()
_registry.register(DPAPIMasterkeyV1Format())
_registry.register(DPAPIMasterkeyV2Format())
