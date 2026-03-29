# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/encoded_base64.py
#  Base64 encoding detection and decoding handler for CTF challenges.
#  Decodes base64 strings and recursively identifies underlying hash content.
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
hashaxe.formats.encoded_base64 — Base64 encoding detection and decoding.

Handles:
  - Standard Base64 (RFC 4648)
  - Base64url (URL-safe variant)
  - Recursive identification of decoded content

Common in CTF challenges where passwords or hints are base64-encoded.
Does not require cracking — decoding reveals the content directly.

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

import base64
import re
import string
from pathlib import Path
from typing import Any

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

# Base64 character sets
_BASE64_STD = set(string.ascii_letters + string.digits + "+/=")
_BASE64_URL = set(string.ascii_letters + string.digits + "-_=")

# Minimum length for base64 detection (avoid false positives on short strings)
_MIN_BASE64_LEN = 16

# Known raw-hash hex digest lengths — reject these from base64 detection
_HASH_HEX_LENS = {32, 40, 56, 64, 96, 128}


def _is_valid_base64(data: str) -> tuple[bool, str]:
    """Check if string is valid base64.

    Returns (is_valid, variant) where variant is 'standard', 'url', or ''.
    """
    data = data.strip()

    if len(data) < _MIN_BASE64_LEN:
        return False, ""

    # Reject pure hex strings that match known hash digest lengths.
    # Without this, MD5 (32 hex chars) and SHA-256 (64 hex chars) get
    # misidentified as base64 because hex chars are valid base64 chars.
    try:
        bytes.fromhex(data)
        if len(data) in _HASH_HEX_LENS:
            return False, ""
    except ValueError:
        pass  # not pure hex — continue with base64 checks

    # Check character set
    chars = set(data)

    # Check for URL-safe base64 (contains - or _)
    if chars & set("-_"):
        if chars <= _BASE64_URL:
            variant = "url"
        else:
            return False, ""
    elif chars <= _BASE64_STD:
        variant = "standard"
    else:
        return False, ""

    # Validate padding (must be 0, 1, or 2 = signs at end)
    if "=" in data:
        padding_count = len(data) - len(data.rstrip("="))
        if padding_count > 2:
            return False, ""
        if not data.endswith("=" * padding_count):
            return False, ""

    # Try to decode
    try:
        if variant == "url":
            # Add padding if needed
            padding = "=" * (4 - len(data) % 4) if len(data) % 4 else ""
            base64.urlsafe_b64decode(data + padding)
        else:
            # Add padding if needed
            padding = "=" * (4 - len(data) % 4) if len(data) % 4 else ""
            base64.b64decode(data + padding)
        return True, variant
    except Exception:
        return False, ""


def _decode_base64(data: str, variant: str) -> bytes | None:
    """Decode base64 string to bytes."""
    try:
        if variant == "url":
            padding = "=" * (4 - len(data) % 4) if len(data) % 4 else ""
            return base64.urlsafe_b64decode(data + padding)
        else:
            padding = "=" * (4 - len(data) % 4) if len(data) % 4 else ""
            return base64.b64decode(data + padding)
    except Exception:
        return None


def _is_printable_text(data: bytes) -> bool:
    """Check if decoded bytes are printable text."""
    try:
        text = data.decode("utf-8")
        printable = set(string.printable)
        # Allow most printable chars plus some unicode
        return sum(1 for c in text if c in printable) / len(text) > 0.9
    except Exception:
        return False


def _extract_potential_password(text: str) -> str | None:
    """Extract potential password from decoded text.

    Looks for patterns like:
    - "The answer is \"password\""
    - "password: secret123"
    - "flag{...}"
    """
    # Look for quoted strings after keywords - most specific first
    patterns = [
        # "The answer to this exercise is "password"" - specific pattern
        r'(?:answer\s+to\s+this\s+\w+\s+is)\s*["\']([^"\']+)["\']',
        # "The answer is "password""
        r'(?:answer|password|pass|key|flag|secret)\s+(?:is|:)[\s]*["\']([^"\']+)["\']',
        # flag{...}
        r"flag\{([^}]+)\}",
        # password: value (without quotes)
        r"password[:\s]+(\S+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


class Base64Format(BaseFormat):
    """Handler for Base64-encoded data.

    This is NOT a hash format — it's an encoding.
    Decoding reveals the content directly, no cracking needed.
    """

    format_id = "encoded.base64"
    format_name = "Base64 Encoded Data"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        # Try to decode as string
        try:
            text = data.decode("utf-8").strip()
        except Exception:
            return None

        is_valid, variant = _is_valid_base64(text)
        if not is_valid:
            return None

        decoded = _decode_base64(text, variant)
        if decoded is None:
            return None

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.40,  # Low: encoding must never outrank real hash/crypto formats
            metadata={
                "variant": variant,
                "decoded_len": len(decoded),
                "is_text": _is_printable_text(decoded),
            },
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8").strip()
        is_valid, variant = _is_valid_base64(text)
        decoded = _decode_base64(text, variant)

        if decoded is None:
            raise ValueError("Failed to decode base64")

        is_text = _is_printable_text(decoded)
        decoded_str = decoded.decode("utf-8", errors="replace") if is_text else None

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"Base64 ({variant}, {len(decoded)} bytes)",
            source_path=str(path) if path else "inline",
            is_encrypted=False,  # It's encoded, not encrypted
            difficulty=FormatDifficulty.TRIVIAL,  # No cracking needed
            format_data={
                "variant": variant,
                "raw_data": data,
                "decoded_bytes": decoded,
                "decoded_len": len(decoded),
                "decoded_text": decoded_str,
                "is_text": is_text,
                "original_b64": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        # Base64 doesn't need verification — it's not a hash
        # But we can check if password matches extracted password
        extracted = target.format_data.get("extracted_password")
        if extracted:
            return password.decode("utf-8", "replace") == extracted
        return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        info = {
            "Format": "Base64 Encoded Data",
            "Variant": target.format_data.get("variant", "standard"),
            "Decoded Length": f"{target.format_data.get('decoded_len', 0)} bytes",
            "Content Type": "Text" if target.format_data.get("is_text") else "Binary",
        }

        decoded_text = target.format_data.get("decoded_text")
        if decoded_text:
            # Truncate for display
            preview = decoded_text[:200] + "..." if len(decoded_text) > 200 else decoded_text
            info["Decoded Preview"] = preview.replace("\n", "\\n")

            # Try to extract password
            extracted = _extract_potential_password(decoded_text)
            if extracted:
                info["Extracted Password"] = extracted
                target.format_data["extracted_password"] = extracted

        return info


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(Base64Format())
