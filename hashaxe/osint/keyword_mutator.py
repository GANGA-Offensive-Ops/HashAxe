# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/osint/keyword_mutator.py
#  Transform OSINT keywords into password candidates using mutation strategies.
#  Generates probable guesses from profile tokens with leet, suffixes, combinations.
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
osint/keyword_mutator.py — Transform OSINT keywords into password candidates.

Takes extracted profile tokens and generates highly-probable password guesses
using intelligent mutation strategies based on real-world password patterns.

Mutation strategies:
  1. Raw tokens (as-is, capitalized, uppercased, lowercased)
  2. Token + year suffixes (2020-2026, birth years)
  3. Token + digit/symbol suffixes (!, 123, @, #1)
  4. Leet speak transformations
  5. Token combinations (first+last name, name+year, etc.)
  6. Initialism patterns (John Smith → JS, js, Js)
  7. Keyboard walk adjacency detection
  8. Reverse and swap mutations
"""
from __future__ import annotations

import itertools
import logging
from collections.abc import Iterator

from hashaxe.osint.nlp_engine import ExtractedProfile

logger = logging.getLogger(__name__)

# ── Leet speak table ──────────────────────────────────────────────────────────

_LEET = str.maketrans({
    "a": "@", "A": "@", "e": "3", "E": "3",
    "i": "1", "I": "1", "o": "0", "O": "0",
    "s": "$", "S": "$", "t": "7", "T": "7",
})

# ── Common password patterns ─────────────────────────────────────────────────

_YEAR_SUFFIXES = [str(y) for y in range(2018, 2027)]
_DIGIT_SUFFIXES = [
    "1", "2", "12", "123", "1234", "12345", "0", "01", "007",
    "11", "22", "69", "99", "100", "00",
]
_SYMBOL_SUFFIXES = [
    "!", "@", "#", "$", ".", "*", "?",
    "!1", "!!", "!@#", "#1", "@1",
    "123!", "1!", "1234!", "!@#$",
]
_SEPARATORS = ["", "_", "-", ".", "@", "#"]
_PREFIXES = ["!", "1", "The", "My", "I", "iLove", "ILove"]


class KeywordMutator:
    """Transform extracted OSINT tokens into password candidate streams.

    This is a generator-based pipeline — it never materializes the full
    candidate list in memory, yielding one candidate at a time.
    """

    def __init__(self, max_length: int = 64, min_length: int = 4):
        self.max_length = max_length
        self.min_length = min_length

    def mutate_profile(self, profile: ExtractedProfile) -> Iterator[str]:
        """Generate all candidates from an OSINT profile, deduplicated."""
        seen: set[str] = set()
        total = 0

        def _emit(candidate: str) -> Iterator[str]:
            nonlocal total
            c = candidate.strip()
            if (
                c
                and c not in seen
                and self.min_length <= len(c) <= self.max_length
            ):
                seen.add(c)
                total += 1
                yield c

        tokens = profile.all_tokens

        # ── Stage 1: Raw tokens with case variants ────────────────────────
        for token in tokens:
            yield from _emit(token)
            yield from _emit(token.lower())
            yield from _emit(token.upper())
            yield from _emit(token.capitalize())
            yield from _emit(token.title())
            yield from _emit(token.swapcase())

        # ── Stage 2: Tokens + year suffixes ───────────────────────────────
        for token in tokens:
            for year in _YEAR_SUFFIXES:
                yield from _emit(token + year)
                yield from _emit(token.capitalize() + year)
            for year in profile.years:
                yield from _emit(token + year)
                yield from _emit(token.capitalize() + year)

        # ── Stage 3: Tokens + digit suffixes ──────────────────────────────
        for token in tokens:
            for suffix in _DIGIT_SUFFIXES:
                yield from _emit(token + suffix)
                yield from _emit(token.capitalize() + suffix)

        # ── Stage 4: Tokens + symbol suffixes ─────────────────────────────
        for token in tokens:
            for suffix in _SYMBOL_SUFFIXES:
                yield from _emit(token + suffix)
                yield from _emit(token.capitalize() + suffix)

        # ── Stage 5: Leet speak ───────────────────────────────────────────
        for token in tokens:
            leet = token.translate(_LEET)
            if leet != token:
                yield from _emit(leet)
                for suffix in ["!", "1", "123", "2024", "2025"]:
                    yield from _emit(leet + suffix)

        # ── Stage 6: Prefix mutations ─────────────────────────────────────
        for token in tokens[:20]:  # Limit combinatorial explosion
            for prefix in _PREFIXES:
                yield from _emit(prefix + token)
                yield from _emit(prefix + token.capitalize())

        # ── Stage 7: Token combinations (name pairs) ──────────────────────
        name_tokens = (profile.names + profile.keywords)[:15]
        for a, b in itertools.permutations(name_tokens, 2):
            for sep in _SEPARATORS[:3]:  # Limit to "", "_", "-"
                yield from _emit(a + sep + b)
                yield from _emit(a.capitalize() + sep + b.capitalize())
                yield from _emit(a.lower() + sep + b.lower())

        # ── Stage 8: Name + year combinations ─────────────────────────────
        for name in profile.names[:10]:
            for year in _YEAR_SUFFIXES:
                for sep in ["", "_"]:
                    yield from _emit(name + sep + year)
                    yield from _emit(name.lower() + sep + year)

        # ── Stage 9: Initialism patterns ──────────────────────────────────
        for name in profile.names:
            parts = name.split()
            if len(parts) >= 2:
                initials = "".join(p[0] for p in parts if p)
                yield from _emit(initials.upper())
                yield from _emit(initials.lower())
                for suffix in _DIGIT_SUFFIXES[:6]:
                    yield from _emit(initials + suffix)
                    yield from _emit(initials.upper() + suffix)

        # ── Stage 10: Email-based patterns ────────────────────────────────
        for email in profile.emails:
            local = email.split("@")[0]
            yield from _emit(local)
            yield from _emit(local + "!")
            yield from _emit(local + "123")
            yield from _emit(local + "2024")
            yield from _emit(local + "2025")

        # ── Stage 11: Date-based patterns ─────────────────────────────────
        for date_str in profile.dates:
            yield from _emit(date_str)
            for name in profile.names[:5]:
                yield from _emit(name.lower() + date_str)
                yield from _emit(date_str + name.lower())

        # ── Stage 12: Reverse and structural ──────────────────────────────
        for token in tokens[:20]:
            yield from _emit(token[::-1])
            yield from _emit(token + token)  # doubled

        logger.info("OSINT mutation complete: %d unique candidates generated", total)

    def estimate_candidates(self, profile: ExtractedProfile) -> int:
        """Rough estimation of candidate count without generating them."""
        n_tokens = len(profile.all_tokens)
        n_names = len(profile.names)
        base = n_tokens * (
            6  # case variants
            + len(_YEAR_SUFFIXES) * 2  # year suffixes
            + len(profile.years) * 2  # personal years
            + len(_DIGIT_SUFFIXES) * 2  # digit suffixes
            + len(_SYMBOL_SUFFIXES) * 2  # symbol suffixes
        )
        combos = min(n_names, 15) ** 2 * 3  # name pairs
        return base + combos
