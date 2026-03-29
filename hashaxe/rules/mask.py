# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/rules/mask.py
#  Mask attack engine for systematic brute-force over password patterns.
#  Implements hashcat-compatible mask syntax with custom charsets.
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
mask.py — Mask attack engine.

Implements hashcat-compatible mask syntax for systematic brute-force
over password patterns.

Mask syntax:
  ?l  — lowercase letters (a-z)
  ?u  — uppercase letters (A-Z)
  ?d  — digits (0-9)
  ?s  — special characters  ( !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~)
  ?a  — all printable ASCII (?l + ?u + ?d + ?s)
  ?b  — all bytes (0x00–0xFF)
  ?1  — custom charset 1 (defined by --custom-charset1 / -1)
  ?2  — custom charset 2 (defined by --custom-charset2 / -2)
  ?3  — custom charset 3
  ?4  — custom charset 4

Examples:
  ?l?l?l?d?d?d        — 3 lowercase + 3 digits  (26³ × 10³ = 17,576,000)
  Pass?d?d?d?d        — "Pass" + 4 digits        (10,000 candidates)
  ?u?l?l?l?d?d        — Capital + 3 lower + 2d   (5,765,760 candidates)
  -1 ?l?d ?1?1?1?1?1  — alphanumeric 5-char      (36^5 = 60,466,176)
"""

from __future__ import annotations

import itertools
import string
from collections.abc import Generator
from typing import Optional

# ── Standard charsets ─────────────────────────────────────────────────────────

CHARSET_LOWER = string.ascii_lowercase  # 26 chars
CHARSET_UPPER = string.ascii_uppercase  # 26 chars
CHARSET_DIGITS = string.digits  # 10 chars
CHARSET_SPECIAL = string.punctuation  # 32 chars
CHARSET_ALL = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL  # 94
CHARSET_BYTES = "".join(chr(i) for i in range(256))  # 256 chars

_STD_CHARSETS = {
    "?l": CHARSET_LOWER,
    "?u": CHARSET_UPPER,
    "?d": CHARSET_DIGITS,
    "?s": CHARSET_SPECIAL,
    "?a": CHARSET_ALL,
    "?b": CHARSET_BYTES,
}


# ── Mask parser ───────────────────────────────────────────────────────────────


class MaskEngine:
    """
    Generates all password candidates matching a hashcat-style mask.

    Usage:
        engine = MaskEngine("Pass?d?d?d?d")
        for candidate in engine.candidates():
            ...

    With custom charsets:
        engine = MaskEngine("?1?1?1?1?1", custom={"?1": "abc123"})
        for candidate in engine.candidates():
            ...
    """

    def __init__(
        self,
        mask: str,
        custom: dict[str, str] | None = None,
    ):
        self.mask = mask
        self.custom = custom or {}
        self._segments = self._parse(mask)

    def _parse(self, mask: str) -> list[str | list[str]]:
        """
        Parse mask string into a list of segments.
        Each segment is either:
          - A list of characters (for ?x placeholders)
          - A literal string character

        Returns list of char-lists.  Literal chars become single-element lists.
        """
        charsets = {**_STD_CHARSETS, **self.custom}
        segments: list[list[str]] = []

        i = 0
        while i < len(mask):
            if mask[i] == "?" and i + 1 < len(mask):
                token = "?" + mask[i + 1]
                if token in charsets:
                    segments.append(list(charsets[token]))
                    i += 2
                    continue
                else:
                    raise ValueError(
                        f"Unknown mask token '{token}' at position {i}.\n"
                        f"  Valid tokens: {list(charsets.keys())}"
                    )
            # Literal character
            segments.append([mask[i]])
            i += 1

        return segments

    def candidate_count(self) -> int:
        """Total number of candidates this mask will generate."""
        count = 1
        for seg in self._segments:
            count *= len(seg)
        return count

    def candidates(self) -> Generator[str, None, None]:
        """Yield every password matching the mask."""
        for combo in itertools.product(*self._segments):
            yield "".join(combo)

    def candidates_from(self, skip: int) -> Generator[str, None, None]:
        """Yield candidates starting from position *skip* (for session resume)."""
        for i, combo in enumerate(itertools.product(*self._segments)):
            if i >= skip:
                yield "".join(combo)

    @staticmethod
    def estimate_size(mask: str, custom: dict[str, str] | None = None) -> int:
        """Quick size estimate without instantiating a full engine."""
        try:
            return MaskEngine(mask, custom).candidate_count()
        except ValueError:
            return 0

    def __repr__(self) -> str:
        return f"MaskEngine({self.mask!r}, candidates={self.candidate_count():,})"


# ── Hybrid mode: wordlist + mask appended ────────────────────────────────────


def hybrid_candidates(
    words: list[str],
    mask: str,
    custom: dict[str, str] | None = None,
) -> Generator[str, None, None]:
    """
    Hybrid attack: for each word in *words*, append all mask combinations.

    Example: words=["puppet"], mask="?d?d?d"  →  "puppet000" … "puppet999"
    """
    engine = MaskEngine(mask, custom)
    for word in words:
        for suffix in engine.candidates():
            yield word + suffix


# ── Incremental mask generator (for --increment mode) ─────────────────────────


def incremental_candidates(
    charset: str = CHARSET_ALL,
    min_len: int = 1,
    max_len: int = 8,
) -> Generator[str, None, None]:
    """
    Brute-force all combinations of *charset* from min_len to max_len.
    Equivalent to hashcat's --increment mode.
    """
    chars = list(charset)
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)
