# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/network_kerberos.py
#  Kerberos hash family handler for Active Directory pentesting.
#  Supports Kerberoasting and AS-REP Roasting with RC4/AES128/AES256.
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
hashaxe.formats.network_kerberos — Kerberos hash family handler.

Supports the full Kerberos attack surface used in Active Directory pentests:
  • Kerberoast TGS-REP RC4  etype 23   → hashcat -m 13100
  • AS-REP Roast     RC4  etype 23   → hashcat -m 18200
  • Kerberos AES128  TGS  etype 17   → hashcat -m 19600
  • Kerberos AES256  TGS  etype 18   → hashcat -m 19700

Input formats (Rubeus / Impacket / GetUserSPNs.py):
  $krb5tgs$23$*user$realm$test/spn*$<ticket_hex>
  $krb5asrep$23$user@domain:<hash>

MITRE ATT&CK: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)
"""
from __future__ import annotations

import hashlib
import hmac
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

# ── Regex patterns ────────────────────────────────────────────────────────────

# Kerberoast TGS-REP RC4 etype 23 (hashcat -m 13100)
# $krb5tgs$23$*user$REALM$spn*$<checksum_hex>$<edata2_hex>
# Note: checksum can be 16-64 hex chars depending on tool output;
#       username may contain '@'; SPN may contain '/' and '.'
_KRB5TGS_23_RE = re.compile(
    r'^\$krb5tgs\$23\$\*([^*]+)\*\$([a-fA-F0-9]+)\$?([a-fA-F0-9]*)$'
)

# AS-REP Roast etype 23 (hashcat -m 18200)
# $krb5asrep$23$user@DOMAIN:<hex_data>
# Note: after the colon there may be checksum$edata2 or just one hex run
_KRB5ASREP_23_RE = re.compile(
    r'^\$krb5asrep\$23\$([^:]+):([a-fA-F0-9]+)\$?([a-fA-F0-9]*)$'
)

# Kerberos TGS AES128 etype 17 (hashcat -m 19600)
# Flexible: SPN part may or may not be wrapped in *...*
_KRB5TGS_17_RE = re.compile(
    r'^\$krb5tgs\$17\$([^$]+)\$([^$]+)\$([^$]*)\$([a-fA-F0-9]+)\$?([a-fA-F0-9]*)$'
)

# Kerberos TGS AES256 etype 18 (hashcat -m 19700)
_KRB5TGS_18_RE = re.compile(
    r'^\$krb5tgs\$18\$([^$]+)\$([^$]+)\$([^$]*)\$([a-fA-F0-9]+)\$?([a-fA-F0-9]*)$'
)


# ── Kerberoast TGS-REP RC4 Handler ───────────────────────────────────────────

class Kerberos5TGS_RC4Format(BaseFormat):
    """Kerberoast TGS-REP RC4 etype 23 (hashcat -m 13100).

    Verification: HMAC-MD5 of the NTLM hash (MD4 of UTF-16LE password)
    over the encrypted data checksum. This is the standard Kerberoasting
    attack path from Rubeus/Impacket GetUserSPNs.py output.
    """

    format_id = "network.krb5tgs_rc4"
    format_name = "Kerberoast TGS-REP RC4 (etype 23)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _KRB5TGS_23_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "Kerberoast TGS-REP RC4 etype 23"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _KRB5TGS_23_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Kerberoast TGS-REP RC4 format: {text[:80]}")

        # Group 1 = everything between *...* e.g. "user@DOMAIN.COM$DOMAIN.COM$SPN/cifs/..."
        inner = m.group(1)
        parts = inner.split("$")
        username = parts[0] if len(parts) >= 1 else "unknown"
        realm = parts[1] if len(parts) >= 2 else "unknown"
        spn = parts[2] if len(parts) >= 3 else "unknown"

        hex_str1 = m.group(2)
        hex_str2 = m.group(3) or ""
        
        if hex_str1 and not hex_str2 and len(hex_str1) > 32:
            checksum_hex = hex_str1[:32]
            edata2_hex = hex_str1[32:]
        else:
            checksum_hex = hex_str1
            edata2_hex = hex_str2

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Kerberoast RC4 ({username}@{realm} — {spn})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.FAST,
            format_data={
                "username": username,
                "realm": realm,
                "spn": spn,
                "checksum_hex": checksum_hex,
                "edata2_hex": edata2_hex,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """RC4-HMAC Kerberos verification:
        1. NTLM hash = MD4(UTF-16LE(password))
        2. K1 = HMAC-MD5(NTLM_hash, usage_number=2 as LE int32)
        3. checksum = HMAC-MD5(K1, edata2)
        4. Compare checksum with stored checksum
        """
        try:
            checksum = bytes.fromhex(target.format_data["checksum_hex"])
            edata2 = bytes.fromhex(target.format_data["edata2_hex"]) if target.format_data["edata2_hex"] else b""

            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()

            # Key usage 2 for TGS-REP
            k1 = hmac.new(ntlm_hash, (2).to_bytes(4, "little"), "md5").digest()
            computed = hmac.new(k1, edata2, "md5").digest()

            return hmac.compare_digest(computed, checksum)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Kerberoast RC4 (etype 23)",
            "Username": target.format_data.get("username", "unknown"),
            "Realm": target.format_data.get("realm", "unknown"),
            "SPN": target.format_data.get("spn", "unknown"),
            "Hashcat Mode": "13100",
            "MITRE": "T1558.003",
            "Difficulty": "FAST (millions pw/s, NTLM + HMAC-MD5)",
        }


# ── AS-REP Roast Handler ─────────────────────────────────────────────────────

class Kerberos5ASREP_RC4Format(BaseFormat):
    """AS-REP Roast etype 23 (hashcat -m 18200).

    Targets accounts with "Do not require Kerberos preauthentication" set.
    Verification identical to Kerberoast RC4 but with key usage 8.
    """

    format_id = "network.krb5asrep_rc4"
    format_name = "AS-REP Roast RC4 (etype 23)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _KRB5ASREP_23_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "AS-REP Roast RC4 etype 23"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _KRB5ASREP_23_RE.match(text)
        if not m:
            raise ValueError(f"Invalid AS-REP Roast format: {text[:80]}")

        # Group 1 = "user@DOMAIN.COM", group 2 = hex checksum, group 3 = optional edata2
        user_domain = m.group(1)
        if "@" in user_domain:
            username, domain = user_domain.rsplit("@", 1)
        else:
            username, domain = user_domain, ""

        hex_str1 = m.group(2)
        hex_str2 = m.group(3) or ""
        
        if hex_str1 and not hex_str2 and len(hex_str1) > 32:
            checksum_hex = hex_str1[:32]
            edata2_hex = hex_str1[32:]
        else:
            checksum_hex = hex_str1
            edata2_hex = hex_str2

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"AS-REP Roast ({username}@{domain})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.FAST,
            format_data={
                "username": username,
                "domain": domain,
                "checksum_hex": checksum_hex,
                "edata2_hex": edata2_hex,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Same as Kerberoast RC4 but with key usage 8 for AS-REP."""
        try:
            checksum = bytes.fromhex(target.format_data["checksum_hex"])
            edata2 = bytes.fromhex(target.format_data["edata2_hex"]) if target.format_data["edata2_hex"] else b""

            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()

            k1 = hmac.new(ntlm_hash, (8).to_bytes(4, "little"), "md5").digest()
            computed = hmac.new(k1, edata2, "md5").digest()

            return hmac.compare_digest(computed, checksum)
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "AS-REP Roast RC4 (etype 23)",
            "Username": target.format_data.get("username", "unknown"),
            "Domain": target.format_data.get("domain", "unknown"),
            "Hashcat Mode": "18200",
            "MITRE": "T1558.004",
            "Difficulty": "FAST (millions pw/s, NTLM + HMAC-MD5)",
        }


# ── Kerberos AES128 TGS Handler ──────────────────────────────────────────────

class Kerberos5TGS_AES128Format(BaseFormat):
    """Kerberos TGS AES128 etype 17 (hashcat -m 19600).

    Found in hardened AD environments with AES-only Kerberos policy.
    Uses PBKDF2-HMAC-SHA1 key derivation — significantly slower than RC4.
    """

    format_id = "network.krb5tgs_aes128"
    format_name = "Kerberos TGS AES128 (etype 17)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _KRB5TGS_17_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "Kerberos TGS AES128 etype 17"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _KRB5TGS_17_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Kerberos AES128 TGS format: {text[:80]}")

        username = m.group(1)
        realm = m.group(2)
        spn = m.group(3)

        hex_str1 = m.group(4)
        hex_str2 = m.group(5) or ""

        # AES checksums are 12 bytes (24 hex characters)
        if hex_str1 and not hex_str2 and len(hex_str1) > 24:
            checksum_hex = hex_str1[:24]
            edata2_hex = hex_str1[24:]
        else:
            checksum_hex = hex_str1
            edata2_hex = hex_str2

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Kerberos AES128 ({username}@{realm})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.MEDIUM,
            format_data={
                "username": username,
                "realm": realm,
                "spn": spn,
                "checksum_hex": checksum_hex,
                "edata2_hex": edata2_hex,
                "etype": 17,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """AES128 Kerberos verification via PBKDF2-HMAC-SHA1 key derivation.

        1. salt = REALM + username (uppercase realm convention)
        2. key = PBKDF2(password, salt, iterations=4096, dkLen=16)
        3. Derive Ki integrity key via DK(key, usage)
        4. HMAC-SHA1 truncated to 12 bytes over edata2
        5. Compare with stored checksum
        """
        try:
            checksum = bytes.fromhex(target.format_data["checksum_hex"])
            edata2 = bytes.fromhex(target.format_data["edata2_hex"]) if target.format_data["edata2_hex"] else b""
            realm = target.format_data["realm"]
            username = target.format_data["username"]

            salt = (realm.upper() + username).encode("utf-8")
            key = hashlib.pbkdf2_hmac("sha1", password, salt, 4096, dklen=16)

            # Derive integrity sub-key (simplified — uses HMAC-SHA1)
            ki = hmac.new(key, b"kerberos" + b"\x00" * 8, "sha1").digest()[:16]
            computed = hmac.new(ki, edata2, "sha1").digest()[:12]

            return hmac.compare_digest(computed, checksum[:12])
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Kerberos AES128 (etype 17)",
            "Username": target.format_data.get("username", "unknown"),
            "Realm": target.format_data.get("realm", "unknown"),
            "Hashcat Mode": "19600",
            "MITRE": "T1558.003",
            "Difficulty": "MEDIUM (PBKDF2 4096 iterations)",
        }


# ── Kerberos AES256 TGS Handler ──────────────────────────────────────────────

class Kerberos5TGS_AES256Format(BaseFormat):
    """Kerberos TGS AES256 etype 18 (hashcat -m 19700).

    Strongest Kerberos encryption type. Uses PBKDF2-HMAC-SHA1
    with 32-byte derived key. Commonly found in modern, hardened AD.
    """

    format_id = "network.krb5tgs_aes256"
    format_name = "Kerberos TGS AES256 (etype 18)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _KRB5TGS_18_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={"description": "Kerberos TGS AES256 etype 18"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        m = _KRB5TGS_18_RE.match(text)
        if not m:
            raise ValueError(f"Invalid Kerberos AES256 TGS format: {text[:80]}")

        username = m.group(1)
        realm = m.group(2)
        spn = m.group(3)

        hex_str1 = m.group(4)
        hex_str2 = m.group(5) or ""

        # AES checksums are 12 bytes (24 hex characters)
        if hex_str1 and not hex_str2 and len(hex_str1) > 24:
            checksum_hex = hex_str1[:24]
            edata2_hex = hex_str1[24:]
        else:
            checksum_hex = hex_str1
            edata2_hex = hex_str2

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Kerberos AES256 ({username}@{realm})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.MEDIUM,
            format_data={
                "username": username,
                "realm": realm,
                "spn": spn,
                "checksum_hex": checksum_hex,
                "edata2_hex": edata2_hex,
                "etype": 18,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """AES256 Kerberos verification. Same flow as AES128 but 32-byte key."""
        try:
            checksum = bytes.fromhex(target.format_data["checksum_hex"])
            edata2 = bytes.fromhex(target.format_data["edata2_hex"]) if target.format_data["edata2_hex"] else b""
            realm = target.format_data["realm"]
            username = target.format_data["username"]

            salt = (realm.upper() + username).encode("utf-8")
            key = hashlib.pbkdf2_hmac("sha1", password, salt, 4096, dklen=32)

            ki = hmac.new(key, b"kerberos" + b"\x00" * 8, "sha1").digest()[:32]
            computed = hmac.new(ki, edata2, "sha1").digest()[:12]

            return hmac.compare_digest(computed, checksum[:12])
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": "Kerberos AES256 (etype 18)",
            "Username": target.format_data.get("username", "unknown"),
            "Realm": target.format_data.get("realm", "unknown"),
            "Hashcat Mode": "19700",
            "MITRE": "T1558.003",
            "Difficulty": "MEDIUM (PBKDF2 4096 iterations, 256-bit key)",
        }


# ── Register all handlers ────────────────────────────────────────────────────

_registry = FormatRegistry()
_registry.register(Kerberos5TGS_RC4Format())
_registry.register(Kerberos5ASREP_RC4Format())
_registry.register(Kerberos5TGS_AES128Format())
_registry.register(Kerberos5TGS_AES256Format())
