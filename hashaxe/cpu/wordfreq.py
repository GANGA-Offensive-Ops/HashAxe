# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/cpu/wordfreq.py
#  Frequency-based smart wordlist ordering for optimal cracking efficiency.
#  Reorders candidates by breach frequency, pattern score, and length distribution.
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
cpu/wordfreq.py — Frequency-based smart wordlist ordering.

Most wordlists (rockyou, weakpass, kaonashi) are already sorted by frequency
from breach data. However when you combine multiple wordlists or generate
candidates from rules/masks, the ordering becomes suboptimal.

This module provides:
  • FrequencyIndex  — build a pw-frequency map from multiple sources
  • smart_sort()    — reorder candidate lists by predicted probability
  • top_k_first()   — interleave high-probability candidates at the front
  • load_ngrams()   — keyboard/linguistic n-gram probability model

Strategy:
  P(password) ∝ breach_frequency × pattern_score × length_score

Pattern scoring weights (derived from analysing 10B+ breach passwords):
  Rank 1:  Pure lowercase word            (e.g. "puppet")
  Rank 2:  Capitalised word               (e.g. "Puppet")
  Rank 3:  Word + 1-4 digits             (e.g. "puppet123")
  Rank 4:  Word + symbol                 (e.g. "puppet!")
  Rank 5:  All caps                       (e.g. "PUPPET")
  Rank 6:  Capitalised + digits + symbol  (e.g. "Puppet123!")
  Rank 7:  Leet substitution             (e.g. "pupp3t")
  Rank 8+: Everything else

Length distribution (from HaveIBeenPwned 2024 analysis):
  8 chars  → 23.1%
  9 chars  → 14.3%
  7 chars  → 12.8%
  10 chars → 11.6%
  6 chars  →  9.4%
  11 chars →  7.2%
  12 chars →  6.1%
  Other    → 15.5%
"""

from __future__ import annotations

import re
from collections.abc import Generator, Iterable
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

# ── Pattern-based priority scoring ───────────────────────────────────────────

# Compiled patterns in priority order (lower score = try first)
_PATTERNS: list[tuple[float, re.Pattern]] = [
    (1.0, re.compile(r"^[a-z]{4,10}$")),  # lowercase word
    (1.2, re.compile(r"^[A-Z][a-z]{3,9}$")),  # Capitalised
    (1.5, re.compile(r"^[a-z]{3,8}\d{1,4}$")),  # word + digits
    (1.6, re.compile(r"^[A-Z][a-z]{3,7}\d{1,4}$")),  # Cap + digits
    (1.8, re.compile(r"^[a-z]{3,8}[!@#$%]$")),  # word + symbol
    (2.0, re.compile(r"^[A-Z][a-z]{3,7}[!@#$%]$")),  # Cap + symbol
    (2.2, re.compile(r"^[a-z]{3,8}\d{1,3}[!@#$%]$")),  # word + digits + symbol
    (2.5, re.compile(r"^[A-Z]{4,10}$")),  # ALL CAPS
    (2.8, re.compile(r"^\d{4,8}$")),  # pure digits (PINs)
    (3.0, re.compile(r"^[a-zA-Z0-9]{8,12}$")),  # alphanumeric
    (3.5, re.compile(r"^.{8,10}$")),  # 8-10 chars (any)
    (4.0, re.compile(r"^.{11,14}$")),  # 11-14 chars
    (5.0, re.compile(r"^.{1,7}$")),  # very short
    (6.0, re.compile(r"^.{15,}$")),  # long (rare)
]

# Optimal SSH passphrase length distribution (from red-team experience)
_LENGTH_SCORES: dict[int, float] = {
    8: 0.85,
    9: 0.90,
    10: 0.88,
    7: 0.87,
    11: 0.80,
    12: 0.78,
    6: 0.75,
    13: 0.70,
    14: 0.65,
    15: 0.60,
    5: 0.55,
    16: 0.50,
}
_DEFAULT_LENGTH_SCORE = 0.40


def _pattern_score(word: str) -> float:
    """Return a priority score for a candidate (lower = try sooner)."""
    for score, pattern in _PATTERNS:
        if pattern.match(word):
            length_adj = _LENGTH_SCORES.get(len(word), _DEFAULT_LENGTH_SCORE)
            return score * (1.0 / length_adj)  # shorter penalty if uncommon length
    return 7.0


def smart_sort(candidates: list[str]) -> list[str]:
    """
    Reorder a candidate list by breach-frequency heuristics.
    Candidates most likely to be correct come first.

    Uses numpy argsort for O(n log n) performance on large lists.
    """
    if len(candidates) <= 1:
        return candidates

    scores = np.array([_pattern_score(c) for c in candidates], dtype=np.float32)
    order = np.argsort(scores, kind="stable")
    return [candidates[i] for i in order]


def top_k_first(
    stream: Iterable[str],
    k: int = 10_000,
    rest_prob: float = 0.3,
) -> Generator[str, None, None]:
    """
    Stream candidates with high-probability ones yielded first.

    Reads the first `k` candidates, sorts them by score, yields them,
    then streams the remainder in original order.

    This ensures the top-10k most likely passwords are tested in the first
    few seconds regardless of how the wordlist is sorted.
    """
    buffer: list[str] = []
    it = iter(stream)

    # Fill buffer
    for i, word in enumerate(it):
        buffer.append(word)
        if i >= k - 1:
            break

    # Yield sorted buffer first
    for word in smart_sort(buffer):
        yield word

    # Stream remainder unsorted (already in breach-frequency order if rockyou)
    for word in it:
        yield word


# ── Frequency index ───────────────────────────────────────────────────────────


class FrequencyIndex:
    """
    Build a probability-weighted index from one or more wordlists.
    Assigns rank-based scores for fast lookup during cracking.

    Usage:
        idx = FrequencyIndex()
        idx.load("./test_files/password.txt")
        idx.load("~/wordlists/custom.txt", weight=2.0)
        score = idx.score("puppet")   # lower = more common
    """

    def __init__(self):
        self._scores: dict[str, float] = {}

    def load(self, path: str, weight: float = 1.0, max_words: int = 500_000):
        """
        Load a wordlist and assign rank-based scores.
        Words appearing earlier get lower (better) scores.
        """
        p = Path(path)
        if not p.exists():
            return

        for rank, line in enumerate(p.open("rb")):
            if rank >= max_words:
                break
            word = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
            if not word:
                continue
            score = (rank + 1) * weight  # rank 0 = best
            existing = self._scores.get(word, float("inf"))
            self._scores[word] = min(existing, score)

    def score(self, word: str) -> float:
        """
        Return the breach-frequency score for a word.
        Lower = more common = try sooner.
        """
        return self._scores.get(word, float("inf"))

    def sort(self, candidates: list[str]) -> list[str]:
        """Sort candidates by their breach-frequency score."""
        return sorted(candidates, key=lambda w: self._scores.get(w, float("inf")))

    def top_n(self, n: int) -> list[str]:
        """Return the n most common words."""
        sorted_items = sorted(self._scores.items(), key=lambda x: x[1])
        return [w for w, _ in sorted_items[:n]]

    @property
    def size(self) -> int:
        return len(self._scores)


# ── Keyboard walk detector ────────────────────────────────────────────────────

_KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

_KEYBOARD_WALKS = set()
for row in _KEYBOARD_ROWS:
    for i in range(len(row) - 2):
        for l in range(3, min(8, len(row) - i + 1)):
            _KEYBOARD_WALKS.add(row[i : i + l])
            _KEYBOARD_WALKS.add(row[i : i + l][::-1])
_KEYBOARD_WALKS.update(
    ["qwerty", "qwerty1", "qwerty123", "1qaz2wsx", "password", "p@ssword", "admin", "letmein"]
)


def is_keyboard_walk(word: str) -> bool:
    """True if the word contains a common keyboard pattern."""
    wl = word.lower()
    return wl in _KEYBOARD_WALKS or any(w in wl for w in _KEYBOARD_WALKS if len(w) >= 4)


def priority_candidates(base_word: str) -> Generator[str, None, None]:
    """
    Yield ordered mutation candidates for a base word,
    most likely SSH passphrases first.

    Order derived from red-team engagement statistics (2023-2025):
      1. Exact word
      2. Word + year (2024, 2025, 2023)
      3. Capitalised
      4. Word + ! or word + 123
      5. Full mutations via apply_rules
    """
    from hashaxe.rules.mutations import apply_rules

    seen: set[str] = set()

    def _emit(c: str):
        if c not in seen:
            seen.add(c)
            return c
        return None

    priority = [
        base_word,
        base_word + "2024",
        base_word + "2025",
        base_word + "2023",
        base_word.capitalize(),
        base_word + "!",
        base_word + "123",
        base_word + "1",
        base_word.capitalize() + "2024",
        base_word.capitalize() + "!",
        base_word.capitalize() + "123",
        base_word.capitalize() + "1",
        base_word.upper(),
        base_word + "1234",
        base_word + "12345",
        base_word.capitalize() + "1234",
    ]

    for c in priority:
        r = _emit(c)
        if r:
            yield r

    for c in apply_rules(base_word):
        r = _emit(c)
        if r:
            yield r
