# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/network_dcc.py
#  Domain Cached Credentials handler for Windows DCC/DCC2 (MS-Cache v1/v2).
#  Extracts from SECURITY hive via secretsdump.py for offline cracking.
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
hashaxe.formats.network_dcc — Domain Cached Credentials handler.

Supports Windows DCC/DCC2 (MS-Cache v1/v2) hashes extracted from
the SECURITY hive via secretsdump.py or other AD tools.

  • DCC  MS Cache v1   → hashcat -m 1100
  • DCC2 MS Cache v2   → hashcat -m 2100

DCC2 uses PBKDF2-HMAC-SHA1 with 10240 iterations by default,
making it significantly slower than raw NTLM cracking.

MITRE ATT&CK: T1003.005 (Cached Domain Credentials)
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

# DCC v1: 32-hex-chars:username  (or just the 32 hex with username context)
_DCC1_RE = re.compile(r"^([a-fA-F0-9]{32}):([a-zA-Z0-9._@\-]+)$")

# DCC2: $DCC2$<iterations>#<username>#<hash_hex_32>
_DCC2_RE = re.compile(r"^\$DCC2\$(\d+)#([^#]+)#([a-fA-F0-9]{32})$")


class DCC1Format(BaseFormat):
    """DCC MS Cache v1 (hashcat -m 1100).

    Used on pre-Vista Windows systems. Fast to hashaxe because it's
    just MD4(MD4(password) + username).

    Input: <32 hex hash>:<username>
    Source: secretsdump.py against SECURITY hive.
    """

    format_id = "network.dcc1"
    format_name = "DCC MS Cache v1"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _DCC1_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.88,
                metadata={"description": "DCC MS Cache v1"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _DCC1_RE.match(text)
        if not m:
            raise ValueError(f"Invalid DCC v1 format: {text[:80]}")

        hash_bytes = bytes.fromhex(m.group(1))
        username = m.group(2)

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"DCC v1 ({username})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={
                "hash": hash_bytes,
                "username": username,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """DCC v1: MD4(MD4(UTF-16LE(password)) + UTF-16LE(lowercase(username)))"""
        expected = target.format_data["hash"]
        username = target.format_data["username"]

        try:
            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()
            user_lower = username.lower().encode("utf-16-le")
            dcc_hash = hashlib.new("md4", ntlm_hash + user_lower, usedforsecurity=False).digest()

            return hmac.compare_digest(dcc_hash, expected)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "DCC MS Cache v1 (MD4)",
            "Username": target.format_data.get("username", "unknown"),
            "Hashcat Mode": "1100",
            "MITRE": "T1003.005",
            "Difficulty": "TRIVIAL (double MD4 — billions pw/s GPU)",
        }


class DCC2Format(BaseFormat):
    """DCC2 MS Cache v2 (hashcat -m 2100).

    Post-Vista cached credentials. Uses PBKDF2-HMAC-SHA1 over the
    DCC1 hash with configurable iterations (default 10240).

    Input: $DCC2$10240#username#<32 hex hash>
    Source: secretsdump.py against SECURITY hive.
    """

    format_id = "network.dcc2"
    format_name = "DCC2 MS Cache v2"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _DCC2_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "DCC2 MS Cache v2"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _DCC2_RE.match(text)
        if not m:
            raise ValueError(f"Invalid DCC2 format: {text[:80]}")

        iterations = int(m.group(1))
        username = m.group(2)
        hash_bytes = bytes.fromhex(m.group(3))

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"DCC2 ({username}, {iterations} iterations)",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={
                "hash": hash_bytes,
                "username": username,
                "iterations": iterations,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """DCC2: PBKDF2(HMAC-SHA1, DCC1_hash_hex, username, iterations, 16)

        1. Compute DCC1: MD4(MD4(UTF-16LE(pw)) + UTF-16LE(lower(user)))
        2. Use hex representation of DCC1 as the PBKDF2 password
        3. Salt = UTF-16LE(lowercase(username))
        4. Derive 16 bytes with specified iterations
        """
        expected = target.format_data["hash"]
        username = target.format_data["username"]
        iterations = target.format_data["iterations"]

        try:
            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()
            user_lower = username.lower().encode("utf-16-le")
            dcc1 = hashlib.new("md4", ntlm_hash + user_lower, usedforsecurity=False).digest()

            # PBKDF2 with DCC1 hash as password, username as salt
            derived = hashlib.pbkdf2_hmac(
                "sha1", dcc1.hex().encode("ascii"), user_lower, iterations, dklen=16
            )

            return hmac.compare_digest(derived, expected)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        iters = target.format_data.get("iterations", 10240)
        return {
            "Algorithm": f"DCC2 MS Cache v2 (PBKDF2 {iters} iters)",
            "Username": target.format_data.get("username", "unknown"),
            "Hashcat Mode": "2100",
            "MITRE": "T1003.005",
            "Difficulty": f"SLOW (PBKDF2 {iters} iterations)",
        }


# ── Register ──────────────────────────────────────────────────────────────────

_registry = FormatRegistry()
_registry.register(DCC1Format())
_registry.register(DCC2Format())
