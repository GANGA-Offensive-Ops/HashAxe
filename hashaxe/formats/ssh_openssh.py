# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/ssh_openssh.py
#  OpenSSH private key format handler for new and legacy PEM formats.
#  Supports Ed25519, RSA, ECDSA, DSA keys with bcrypt-KDF encryption.
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
hashaxe.formats.ssh_openssh — Format handler for OpenSSH private keys.

Handles:
  • OpenSSH new format (openssh-key-v1)  — Ed25519, RSA, ECDSA, DSA
  • OpenSSH legacy PEM format            — RSA, ECDSA, DSA

Uses the existing ``hashaxe.parser`` and ``hashaxe.engine`` modules
internally via composition — no code duplication.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from hashaxe.engine import try_passphrase, try_passphrase_full
from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)
from hashaxe.parser import (
    _LEGACY_HEADERS,
    KeyFormat,
    ParsedKey,
    _parse_openssh_legacy,
    _parse_openssh_new,
)

logger = logging.getLogger(__name__)

# ── Magic bytes for identification ────────────────────────────────────────────
_OPENSSH_NEW_MAGIC = b"-----BEGIN OPENSSH PRIVATE KEY-----"
_LEGACY_RSA_MAGIC = b"-----BEGIN RSA PRIVATE KEY-----"
_LEGACY_EC_MAGIC = b"-----BEGIN EC PRIVATE KEY-----"
_LEGACY_DSA_MAGIC = b"-----BEGIN DSA PRIVATE KEY-----"

_ALL_OPENSSH_MARKERS = (
    _OPENSSH_NEW_MAGIC,
    _LEGACY_RSA_MAGIC,
    _LEGACY_EC_MAGIC,
    _LEGACY_DSA_MAGIC,
)

_MARKER_TO_HINT: dict[bytes, str] = {
    _LEGACY_RSA_MAGIC: "ssh-rsa",
    _LEGACY_EC_MAGIC: "ecdsa",
    _LEGACY_DSA_MAGIC: "ssh-dss",
}


class OpenSSHFormat(BaseFormat):
    """
    Format handler for OpenSSH private keys (new format + legacy PEM).

    Identification:  Matches on PEM header magic bytes with confidence 1.0.
    Parsing:         Delegates to ``hashaxe.parser`` internal functions.
    Verification:    Delegates to ``hashaxe.engine.try_passphrase()``
                     and ``try_passphrase_full()``.
    """

    format_id = "ssh.openssh"
    format_name = "OpenSSH Private Key"

    # ── Identification ────────────────────────────────────────────────────

    def can_handle(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatMatch | None:
        """
        Detect OpenSSH keys by PEM header markers.

        Returns confidence 1.0 for exact magic byte matches.
        """
        for marker in _ALL_OPENSSH_MARKERS:
            if marker in data:
                # Determine sub-type for metadata
                if marker == _OPENSSH_NEW_MAGIC:
                    variant = "openssh-new"
                elif marker == _LEGACY_RSA_MAGIC:
                    variant = "legacy-rsa"
                elif marker == _LEGACY_EC_MAGIC:
                    variant = "legacy-ecdsa"
                else:
                    variant = "legacy-dsa"

                return FormatMatch(
                    format_id=self.format_id,
                    confidence=1.0,
                    handler=self,
                    metadata={"variant": variant},
                )

        return None

    # ── Parsing ───────────────────────────────────────────────────────────

    def parse(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatTarget:
        """
        Parse an OpenSSH private key file into a FormatTarget.

        Delegates to the existing parser module and wraps the result
        in a FormatTarget with the ParsedKey stored for engine.py access.
        """
        # Normalise line endings (Windows SMB shares, copy-paste, etc.)
        raw = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").rstrip()

        # Route to the correct internal parser
        if _OPENSSH_NEW_MAGIC in raw:
            pk = _parse_openssh_new(raw)
        else:
            # Legacy PEM — find which marker matched and pass its type hint
            matched_hint = ""
            for marker, hint in _MARKER_TO_HINT.items():
                if marker in raw:
                    matched_hint = hint
                    break
            if not matched_hint:
                raise ValueError("No OpenSSH key markers found in data")
            pk = _parse_openssh_legacy(raw, matched_hint)

        # Determine difficulty based on KDF
        if pk.fmt == KeyFormat.OPENSSH_NEW and pk.kdfname == b"bcrypt":
            difficulty = FormatDifficulty.MEDIUM
        elif pk.fmt == KeyFormat.OPENSSH_LEGACY:
            difficulty = FormatDifficulty.FAST
        else:
            difficulty = FormatDifficulty.FAST  # unencrypted

        # Build display info
        display_name = f"OpenSSH {pk.key_type}"
        if pk.ciphername:
            cipher = pk.ciphername.decode("ascii", errors="replace")
        else:
            cipher = "none"

        return FormatTarget(
            format_id=self.format_id,
            display_name=display_name,
            source_path=str(path) if path else "",
            is_encrypted=pk.is_encrypted,
            difficulty=difficulty,
            format_data={
                "key_type": pk.key_type,
                "cipher": cipher,
                "kdf": pk.kdf,
                "rounds": pk.rounds,
                "fmt": pk.fmt.name,
            },
            _legacy_pk=pk,
        )

    # ── Verification ──────────────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """
        Fast-path OpenSSH password check via checkints or PKCS7 padding.

        Delegates to ``engine.try_passphrase()`` using the stored ParsedKey.
        """
        pk = target._legacy_pk
        if pk is None:
            return False
        return try_passphrase(pk, password)

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """
        Full confirmation via cryptography library's official parser.

        Delegates to ``engine.try_passphrase_full()``.
        """
        pk = target._legacy_pk
        if pk is None:
            return False
        return try_passphrase_full(pk, password)

    # ── Metadata ──────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        data = target.format_data
        result: dict[str, str] = {
            "Type": data.get("key_type", "unknown"),
            "Cipher": data.get("cipher", "none"),
            "KDF": data.get("kdf", "none"),
        }
        rounds = data.get("rounds", 0)
        if rounds:
            result["Rounds"] = str(rounds)
        return result


# ── Auto-register on import ───────────────────────────────────────────────────
FormatRegistry().register(OpenSSHFormat())
