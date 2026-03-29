# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/network_ntlm.py
#  NetNTLMv1/v2 challenge-response format handler for network authentication.
#  Captured via Responder, ntlmrelayx, or SMB relay attacks.
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
NetNTLMv1/v2 challenge-response format handler.

NetNTLMv2 format (from Responder, ntlmrelayx, etc.):
  username::domain:server_challenge:ntproofstr:blob
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

# NetNTLMv2: user::domain:challenge:ntproofstr:blob
# Typically has 6 colon-separated fields
_NTLMV2_RE = re.compile(
    r"^[^:]+::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$"
)

# NetNTLMv1: user::domain:lm_response:nt_response:challenge
# LM/NT response can be 16-48+ hex chars depending on tool output
_NTLMV1_RE = re.compile(
    r"^[^:]+::[^:]*:[0-9a-fA-F]{16,}:[0-9a-fA-F]{16,}:[0-9a-fA-F]{16}$"
)


class NetNTLMFormat(BaseFormat):
    """Handler for NetNTLMv1/v2 challenge-response hashes.

    v2: HMAC-MD5 based — medium speed
    v1: DES-based — faster
    """

    format_id   = "network.netntlm"
    format_name = "NetNTLMv1/v2"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _NTLMV2_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.92,
                metadata={"description": "NetNTLMv2 challenge-response"},
            )
        if _NTLMV1_RE.match(text):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.92,
                metadata={"description": "NetNTLMv1 challenge-response"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        parts = text.split(":")

        is_v2 = _NTLMV2_RE.match(text) is not None
        version = "v2" if is_v2 else "v1"

        if is_v2:
            # user::domain:server_challenge:ntproofstr:blob
            username = parts[0]
            domain = parts[2]
            server_challenge = bytes.fromhex(parts[3]) if len(parts) > 3 and parts[3] else b""
            nt_proof_str = bytes.fromhex(parts[4]) if len(parts) > 4 and parts[4] else b""
            blob = bytes.fromhex(parts[5]) if len(parts) > 5 and parts[5] else b""
        else:
            # user::domain:lm_resp:nt_resp:challenge
            username = parts[0]
            domain = parts[2]
            lm_response = bytes.fromhex(parts[3]) if len(parts) > 3 and parts[3] else b""
            blob = bytes.fromhex(parts[4]) if len(parts) > 4 and parts[4] else b""
            server_challenge = bytes.fromhex(parts[5]) if len(parts) > 5 and parts[5] else b""
            nt_proof_str = b""

        return FormatTarget(
            format_id="network.ntlmv2" if is_v2 else "network.ntlmv1",
            display_name=f"NetNTLM{version} ({username}@{domain})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.FAST,
            format_data={
                "target_hash": text,
                "version": version,
                "username": username,
                "domain": domain,
                "server_challenge": server_challenge,
                "lm_response": lm_response if not is_v2 else b"",
                "nt_proof_str": nt_proof_str,
                "blob": blob,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        version = target.format_data["version"]
        if version == "v2":
            return self._verify_v2(target, password)
        return self._verify_v1(target, password)

    def _verify_v2(self, target: FormatTarget, password: bytes) -> bool:
        """NetNTLMv2 verification:
        1. NTLM hash = MD4(UTF-16LE(password))
        2. NTv2 hash = HMAC-MD5(NTLM_hash, UPPERCASE(user) + domain)
        3. NT proof = HMAC-MD5(NTv2_hash, server_challenge + blob)
        4. Compare NT proof with stored nt_proof_str
        """
        username = target.format_data["username"]
        domain = target.format_data["domain"]
        server_challenge = target.format_data["server_challenge"]
        expected_proof = target.format_data["nt_proof_str"]
        blob = target.format_data["blob"]

        try:
            # Step 1: NTLM hash
            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()

            # Step 2: NTv2 hash
            identity = (username.upper() + domain).encode("utf-16-le")
            ntv2_hash = hmac.new(ntlm_hash, identity, "md5").digest()

            # Step 3: NT proof
            nt_proof = hmac.new(ntv2_hash, server_challenge + blob, "md5").digest()

            return hmac.compare_digest(nt_proof, expected_proof)
        except (ValueError, Exception):
            return False

    def _verify_v1(self, target: FormatTarget, password: bytes) -> bool:
        """NetNTLMv1 verification:
        1. NTLM hash = MD4(UTF-16LE(password))
        2. Pad NTLM hash to 21 bytes
        3. Split into 3 × 7-byte DES keys
        4. DES-ECB encrypt server_challenge with each key
        5. Concatenate → NT response (24 bytes)
        6. Compare with stored nt_response (blob field)
        """
        import struct
        from Crypto.Cipher import DES

        server_challenge = target.format_data["server_challenge"]
        # blob stores the nt_response (parsed from parts[4] in v1)
        expected_nt_response = target.format_data["blob"]

        if not server_challenge or not expected_nt_response:
            return False

        try:
            # Step 1: NTLM hash
            pw_utf16 = password.decode("utf-8", "replace").encode("utf-16-le")
            ntlm_hash = hashlib.new("md4", pw_utf16, usedforsecurity=False).digest()

            # Step 2: Pad to 21 bytes
            padded = ntlm_hash + b'\x00' * (21 - len(ntlm_hash))

            # Step 3-4: 3 DES keys from 21 bytes, encrypt challenge
            def des_key_from_7(raw7: bytes) -> bytes:
                """Expand 7 bytes to 8-byte DES key with parity bits."""
                key = bytearray(8)
                key[0] = raw7[0] >> 1
                key[1] = ((raw7[0] & 0x01) << 6) | (raw7[1] >> 2)
                key[2] = ((raw7[1] & 0x03) << 5) | (raw7[2] >> 3)
                key[3] = ((raw7[2] & 0x07) << 4) | (raw7[3] >> 4)
                key[4] = ((raw7[3] & 0x0F) << 3) | (raw7[4] >> 5)
                key[5] = ((raw7[4] & 0x1F) << 2) | (raw7[5] >> 6)
                key[6] = ((raw7[5] & 0x3F) << 1) | (raw7[6] >> 7)
                key[7] = raw7[6] & 0x7F
                # Set parity bits
                for i in range(8):
                    key[i] = (key[i] << 1) & 0xFE
                return bytes(key)

            response = b''
            for i in range(3):
                des_key = des_key_from_7(padded[i*7:(i+1)*7])
                cipher = DES.new(des_key, DES.MODE_ECB)
                response += cipher.encrypt(server_challenge)

            return response == expected_nt_response
        except ImportError:
            # PyCryptodome not available — try pure-Python DES or skip
            return False
        except (ValueError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": f"NetNTLM{target.format_data.get('version', '?')}",
            "Username": target.format_data.get("username", "unknown"),
            "Domain": target.format_data.get("domain", "unknown"),
            "Difficulty": "FAST (hundreds of thousands pw/s)",
        }


_registry = FormatRegistry()
_registry.register(NetNTLMFormat())
