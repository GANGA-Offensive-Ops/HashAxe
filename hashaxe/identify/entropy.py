# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/entropy.py
#  Shannon entropy analysis and charset classification for ambiguous inputs.
#  Statistical fallback when magic bytes and regex patterns fail to identify.
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
Shannon entropy analysis and charset classification for ambiguous inputs.

When magic bytes and regex patterns fail to identify a hash format,
entropy analysis provides a statistical fallback — high-entropy hex strings
are almost certainly hashes, not natural language.
"""
from __future__ import annotations

import math
import string
from typing import NamedTuple


class EntropyResult(NamedTuple):
    """Result of entropy + charset analysis on an input string."""
    entropy: float          # Shannon entropy in bits-per-char
    charset: str            # 'hex_lower', 'hex_mixed', 'base64', 'printable', 'binary'
    char_count: int         # Unique characters observed
    is_likely_hash: bool    # True if characteristics match a raw hash digest
    confidence: float       # 0.0–1.0 confidence that this is a hash


# Charset sets
_HEX_LOWER  = set(string.hexdigits[:16])   # 0-9a-f
_HEX_UPPER  = set(string.hexdigits[16:])   # A-F (without 0-9)
_HEX_ALL    = set(string.hexdigits)
_BASE64     = set(string.ascii_letters + string.digits + "+/=")
_PRINTABLE  = set(string.printable)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character.

    H(X) = -Σ p(x) * log2(p(x))

    Random hex string (16 chars): ~4.0 bits/char
    English text:                 ~3.0-3.5 bits/char
    Random password:              ~5.0-6.0 bits/char
    Single repeated char:         0.0 bits/char
    """
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def classify_charset(data: str) -> str:
    """Classify the character set of an input string.

    Returns one of: 'hex_lower', 'hex_upper', 'hex_mixed',
    'base64', 'printable', 'binary'.
    """
    chars = set(data)

    # Pure lowercase hex (most common for hashes)
    if chars <= (_HEX_LOWER | set(string.digits)):
        return "hex_lower"

    # Pure uppercase hex
    if chars <= (_HEX_UPPER | set(string.digits)):
        return "hex_upper"

    # Mixed case hex
    if chars <= _HEX_ALL:
        return "hex_mixed"

    # Base64 (including padding)
    if chars <= _BASE64:
        return "base64"

    # General printable
    if chars <= _PRINTABLE:
        return "printable"

    return "binary"


# Known hash digest lengths in hex characters
_HASH_LENGTHS: dict[int, list[str]] = {
    32:  ["MD5", "NTLM", "MD4"],
    40:  ["SHA-1", "MySQL native"],
    56:  ["SHA-224", "SHA3-224"],
    64:  ["SHA-256", "SHA3-256"],
    96:  ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "Whirlpool"],
}


def analyze(data: str) -> EntropyResult:
    """Perform full entropy and charset analysis on an input string.

    This is the primary fallback classifier when magic bytes and regex
    patterns fail to identify the format. It determines if a string
    is likely a raw hash digest based on:
    1. Shannon entropy (high = random = likely hash)
    2. Character set (hex = likely hash)
    3. Length matching known digest sizes
    """
    data = data.strip()
    if not data:
        return EntropyResult(
            entropy=0.0, charset="binary", char_count=0,
            is_likely_hash=False, confidence=0.0,
        )

    entropy = shannon_entropy(data)
    charset = classify_charset(data)
    char_count = len(set(data))
    length = len(data)

    # Scoring system: accumulate confidence
    confidence = 0.0
    is_hash = False

    # High entropy in hex charset → very likely a hash
    if charset in ("hex_lower", "hex_upper", "hex_mixed"):
        confidence += 0.3

        # Check for known hash lengths
        if length in _HASH_LENGTHS:
            confidence += 0.4
        elif length in (16, 20, 48):
            # Less common but possible (half-hashes, truncated)
            confidence += 0.15

        # Entropy check: random hex ≈ 3.8-4.0 bits/char
        if entropy >= 3.5:
            confidence += 0.2
        elif entropy >= 3.0:
            confidence += 0.1

        # Character distribution check
        if char_count >= 12:
            confidence += 0.1

    elif charset == "base64":
        # Base64-encoded hashes are common in bcrypt, scrypt, etc.
        if entropy >= 4.5:
            confidence += 0.2

    # Clamp and decide
    confidence = min(confidence, 1.0)
    is_hash = confidence >= 0.5

    return EntropyResult(
        entropy=entropy,
        charset=charset,
        char_count=char_count,
        is_likely_hash=is_hash,
        confidence=confidence,
    )


def suggest_hash_type(data: str) -> list[str]:
    """Given a hex string, suggest possible hash types based on length.

    Returns a list of candidate hash algorithm names, ordered by
    likelihood (most common first).
    """
    data = data.strip()
    length = len(data)
    return list(_HASH_LENGTHS.get(length, []))
