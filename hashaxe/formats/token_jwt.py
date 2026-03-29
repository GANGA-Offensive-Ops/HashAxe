# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/token_jwt.py
#  JWT HMAC token format handler for verifying JWT signatures.
#  Supports HS256, HS384, HS512 — password is the HMAC secret key.
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
JWT HMAC token format handler — verify JWT signatures.

Supports HMAC-SHA256 (HS256), HMAC-SHA384 (HS384), HMAC-SHA512 (HS512).
The "password" is the HMAC secret key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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

# JWT is 3 base64url-encoded parts separated by dots
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

_HMAC_ALGOS = {
    "HS256": ("sha256", hashlib.sha256),
    "HS384": ("sha384", hashlib.sha384),
    "HS512": ("sha512", hashlib.sha512),
}


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class JWTFormat(BaseFormat):
    """Handler for JWT HMAC tokens.

    Cracks the HMAC secret key by brute-forcing signatures.
    """

    format_id = "token.jwt"
    format_name = "JWT (HMAC-SHA256/384/512)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if not _JWT_RE.match(text):
            return None

        # Try to decode the header to confirm it's a JWT
        parts = text.split(".")
        try:
            header = json.loads(_b64url_decode(parts[0]))
            alg = header.get("alg", "")
            if alg in _HMAC_ALGOS:
                return FormatMatch(
                    format_id=self.format_id,
                    handler=self,
                    confidence=0.92,
                    metadata={"description": f"JWT token ({alg})"},
                )
            elif alg:
                # Non-HMAC JWT (RSA, EC) — we can detect but can't hashaxe
                return FormatMatch(
                    format_id=self.format_id,
                    handler=self,
                    confidence=0.5,
                    metadata={"description": f"JWT token ({alg} — not HMAC, cannot hashaxe)"},
                )
        except (json.JSONDecodeError, Exception):
            pass
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()
        parts = text.split(".")

        header = json.loads(_b64url_decode(parts[0]))
        alg = header.get("alg", "HS256")

        if alg not in _HMAC_ALGOS:
            return FormatTarget(
                format_id=self.format_id,
                display_name=f"JWT ({alg} — unsupported for cracking)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,  # Can't hashaxe non-HMAC
                difficulty=FormatDifficulty.MEDIUM,
                format_data={"algorithm": alg, "error": "Non-HMAC algorithm"},
            )

        # The signing input is header.payload (first two parts)
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        signature = _b64url_decode(parts[2])

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"JWT ({alg})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.FAST,
            format_data={
                "algorithm": alg,
                "signing_input_hex": signing_input.hex(),
                "signature_hex": signature.hex(),
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Compute HMAC with candidate secret and compare to JWT signature."""
        alg = target.format_data.get("algorithm", "HS256")
        if alg not in _HMAC_ALGOS:
            return False

        hash_name = _HMAC_ALGOS[alg][0]
        signing_input = bytes.fromhex(target.format_data["signing_input_hex"])
        expected = bytes.fromhex(target.format_data["signature_hex"])

        computed = hmac.new(password, signing_input, hash_name).digest()
        return hmac.compare_digest(computed, expected)

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.FAST

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        signing_hex = target.format_data.get("signing_input_hex", "")
        return {
            "Algorithm": target.format_data.get("algorithm", "HS256"),
            "Signing Input": str(len(signing_hex) // 2) + " bytes",
            "Difficulty": "FAST (millions pw/s)",
        }


_registry = FormatRegistry()
_registry.register(JWTFormat())
