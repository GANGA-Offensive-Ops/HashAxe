# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/token_ansible.py
#  Ansible Vault encrypted file handler for automation secrets.
#  Uses AES-256-CTR with HMAC-SHA256 and PBKDF2 10000 iterations.
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
hashaxe.formats.token_ansible — Ansible Vault encrypted file handler.

Ansible Vault uses AES-256-CTR with HMAC-SHA256, key derived via PBKDF2
with 10000 iterations. The vault format is a distinctive text header:
  $ANSIBLE_VAULT;1.1;AES256
  <hex encoded ciphertext>

Hashcat mode: -m 16900
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

# Ansible Vault header pattern
_VAULT_HEADER_RE = re.compile(r"^\$ANSIBLE_VAULT;(\d+\.\d+);(AES\d*)\s*$", re.MULTILINE)

# Full vault format: header + hex lines
_VAULT_FULL_RE = re.compile(
    r"^\$ANSIBLE_VAULT;(\d+\.\d+);(AES\d*)\s*\n" r"([0-9a-f\n]+)\s*$",
    re.MULTILINE,
)


class AnsibleVaultFormat(BaseFormat):
    """Handler for Ansible Vault encrypted files.

    Uses AES-256-CTR + HMAC-SHA256 with PBKDF2 (10000 iterations).
    The entire file content is encrypted — password required to read anything.
    """

    format_id = "token.ansible_vault"
    format_name = "Ansible Vault (AES-256-CTR)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, AttributeError):
            return None

        if _VAULT_HEADER_RE.search(text):
            m = _VAULT_HEADER_RE.search(text)
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=1.0,
                metadata={
                    "description": f"Ansible Vault v{m.group(1)} ({m.group(2)})",
                },
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict")

        m = _VAULT_HEADER_RE.search(text)
        if not m:
            raise ValueError("Not a valid Ansible Vault file")

        version = m.group(1)
        cipher = m.group(2)

        # Extract the hex payload (everything after the header line)
        lines = text.strip().split("\n")
        hex_data = "".join(line.strip() for line in lines[1:])

        # Ansible vault hex contains: salt + hmac + ciphertext
        # Each separated by newlines in the hex encoding
        vault_parts = hex_data.split("0a")  # 0a = newline in hex

        vault_body = bytes.fromhex(hex_data) if len(hex_data) % 2 == 0 else b""

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Ansible Vault v{version} ({cipher})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={
                "version": version,
                "cipher": cipher,
                "hex_payload": hex_data,
                "vault_body": vault_body,
                "raw_text": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Ansible Vault verification:
        1. PBKDF2(password, salt, 10000, dklen=80)
        2. Split derived key: key1(32) + hmac_key(32) + iv(16)
        3. HMAC-SHA256(hmac_key, ciphertext) == stored_hmac
        """
        hex_payload = target.format_data.get("hex_payload", "")
        if not hex_payload:
            return False

        try:
            hex_payload = target.format_data.get("hex_payload", "")
            if not hex_payload:
                return False

            # Decode the outer hex wrapper
            inner_text = bytes.fromhex(hex_payload).decode("utf-8")

            # The inner text is: salt_hex \n hmac_hex \n ciphertext_hex
            inner_lines = inner_text.strip().split("\n")
            if len(inner_lines) < 3:
                return False

            salt = bytes.fromhex(inner_lines[0])
            stored_hmac = bytes.fromhex(inner_lines[1])
            ciphertext = bytes.fromhex(inner_lines[2])

            # PBKDF2 key derivation (80 bytes: 32 key + 32 hmac_key + 16 iv)
            derived = hashlib.pbkdf2_hmac("sha256", password, salt, 10000, dklen=80)
            hmac_key = derived[32:64]

            computed_hmac = hmac.new(hmac_key, ciphertext, "sha256").digest()
            return hmac.compare_digest(computed_hmac, stored_hmac)
        except (ValueError, Exception):
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Format": "Ansible Vault",
            "Version": target.format_data.get("version", "unknown"),
            "Cipher": target.format_data.get("cipher", "AES256"),
            "KDF": "PBKDF2-SHA256 (10000 iterations)",
            "Hashcat Mode": "16900",
            "Difficulty": "SLOW (PBKDF2 10000 + AES-256-CTR + HMAC-SHA256)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(AnsibleVaultFormat())
