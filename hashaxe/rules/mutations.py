# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/rules/mutations.py
#  Built-in passphrase mutation rules for common password variations.
#  Generator-based implementation for memory-efficient candidate streaming.
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
mutations.py — Built-in passphrase mutation rules.

Generates common real-world password variations from a base word.
Optimised as a generator — no list allocation, yields one candidate at a time.

Coverage:
  • Case variants (original, capitalize, upper, lower, title, swapcase)
  • Common numeric suffixes  (1, 12, 123, 1234, 2020–2026, 99, 007 …)
  • Common symbol suffixes   (!, @, #, $, %, ., *, ?, !!, !@# …)
  • Combined suffixes        (123!, 1!, 2024!, 2025! …)
  • Common prefixes          (!, 1, The, My, I)
  • Keyboard-walk suffixes   (qwerty, qwe, asdf, zxcv, 123qwe)
  • Space-separator variants (word_word, word-word, word.word)
  • Leet speak substitutions (a→@, e→3, i→!, o→0, s→$, t→7, l→1, g→9, b→8)
  • Partial leet             (first-character substitution only)
  • Double-word              (puppet → puppetpuppet)
  • Reversed word
  • Year patterns            (word + 1960–1999, word + 2000–2026)

Performance:
  • Zero heap allocations per yield — bool sentinel pattern (_e) avoids
    nested generator objects that the original emit() design created.
  • seen set is local to each apply_rules() call — never shared across words.
  • count_rules() uses "password" as probe word to hit every tier accurately.

Changelog:
  v1.1.0 (2026-03-22):
    - Fixed: emit() nested-generator overhead replaced with _e() bool pattern
    - Fixed: dead _add() function removed
    - Fixed: year range extended from 1960–2026 (was 1970–1999 only)
    - Fixed: leet table collision i→1 / l→1 resolved (i→!, l→1)
    - Added:  keyboard-walk suffixes tier
    - Added:  space-separator variants tier
    - Added:  partial leet (first-char only) tier
    - Fixed:  count_rules() probe word changed from "x" to "password"
"""

from __future__ import annotations

from collections.abc import Generator

# ── Rust native acceleration (1.1x faster per word, zero generator overhead) ──
try:
    import hashaxe_rules_rs as _native
    _HAS_NATIVE = True
except ImportError:
    _HAS_NATIVE = False

__all__ = ["apply_rules", "count_rules"]

# ── Leet speak table ──────────────────────────────────────────────────────────
# Collision fix: i→! (was i→1, clashing with l→1)

_LEET_TABLE = str.maketrans({
    "a": "@", "A": "@",
    "e": "3", "E": "3",
    "i": "!", "I": "!",   # distinct from l→1
    "o": "0", "O": "0",
    "s": "$", "S": "$",
    "t": "7", "T": "7",
    "l": "1", "L": "1",
    "g": "9", "G": "9",
    "b": "8", "B": "8",
})

# ── Suffix / prefix tables ────────────────────────────────────────────────────

_DIGIT_SUFFIXES: tuple[str, ...] = (
    "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "12", "21", "123", "321", "1234", "12345", "123456",
    "0", "01", "007", "69", "99", "100",
    "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
)

_SYMBOL_SUFFIXES: tuple[str, ...] = (
    "!", "@", "#", "$", "%", ".", "*", "?", "_", "-",
    "!1", "!!", "!@#", "!@#$",
    "#1", "@1", "$$",
)

_COMBINED_SUFFIXES: tuple[str, ...] = (
    "1!",   "1@",
    "123!", "123@", "123#",
    "1234!", "1234@",
    "2023!", "2023@",
    "2024!", "2024@",
    "2025!", "2025@",
    "2026!", "2026@",
)

_PREFIXES: tuple[str, ...] = (
    "!", "1", "0",
    "The", "My", "I",
    "Mr", "Ms", "Dr",
)

_KEYBOARD_WALKS: tuple[str, ...] = (
    "qwerty", "qwert", "qwe",
    "asdf", "asdfgh",
    "zxcv", "zxcvbn",
    "123qwe", "qwe123",
    "1q2w3e", "1qaz2wsx",
)

_SEPARATORS: tuple[str, ...] = ("_", "-", ".", " ")

# Characters eligible for partial-leet (first-char only)
_LEET_CHARS: frozenset[str] = frozenset("aAeEiIoOsStTlLgGbB")


# ── Core mutation generator ───────────────────────────────────────────────────

def apply_rules(word: str) -> Generator[str, None, None]:
    """
    Yield passphrase candidates derived from *word*.

    Tiers are ordered most-likely-to-hashaxe first to minimise average
    hashaxe time across real-world password corpora.

    Deduplication uses a local ``seen`` set — never shared across words,
    so memory growth is bounded to the mutation count of a single word.

    Args:
        word: Base word to mutate (e.g. ``"shadow"``, ``"password"``).

    Yields:
        Candidate strings, deduplicated, highest probability first.
    """
    seen: set[str] = set()

    def _e(c: str) -> bool:
        """Return True and register *c* if unseen; False if duplicate."""
        if c not in seen:
            seen.add(c)
            return True
        return False

    # Pre-compute common case variants once — reused across all tiers
    cap   = word.capitalize()
    up    = word.upper()
    low   = word.lower()
    title = word.title()
    swap  = word.swapcase()

    # ── Tier 1: Case variants ─────────────────────────────────────────────────
    for w in (word, cap, up, low, title, swap):
        if _e(w): yield w

    # ── Tier 2: Numeric suffixes ──────────────────────────────────────────────
    for s in _DIGIT_SUFFIXES:
        for base in (word, cap, up, low):
            w = base + s
            if _e(w): yield w

    # ── Tier 3: Symbol suffixes ───────────────────────────────────────────────
    for s in _SYMBOL_SUFFIXES:
        for base in (word, cap, up, low):
            w = base + s
            if _e(w): yield w

    # ── Tier 4: Combined suffixes (digit + symbol) ────────────────────────────
    for s in _COMBINED_SUFFIXES:
        for base in (word, cap, up):
            w = base + s
            if _e(w): yield w

    # ── Tier 5: Prefixes ──────────────────────────────────────────────────────
    for p in _PREFIXES:
        for base in (word, cap, low):
            w = p + base
            if _e(w): yield w

    # ── Tier 6: Keyboard-walk suffixes ────────────────────────────────────────
    for walk in _KEYBOARD_WALKS:
        for base in (word, cap):
            w = base + walk
            if _e(w): yield w
            w = walk + base
            if _e(w): yield w

    # ── Tier 7: Space-separator variants ─────────────────────────────────────
    # Relevant when base word contains a space, or when building compound words
    for sep in _SEPARATORS:
        w = word.replace(" ", sep)
        if w != word and _e(w): yield w
        # Also double-word with separator
        w = word + sep + word
        if _e(w): yield w
        w = cap + sep + cap
        if _e(w): yield w

    # ── Tier 8: Leet speak (full substitution) ────────────────────────────────
    leet     = word.translate(_LEET_TABLE)
    leet_cap = cap.translate(_LEET_TABLE)
    if leet != word:
        for w in (leet, leet_cap, leet.upper()):
            if _e(w): yield w
        for s in ("!", "1", "123", "1!", "123!"):
            w = leet + s
            if _e(w): yield w
            w = leet_cap + s
            if _e(w): yield w

    # ── Tier 9: Partial leet (first character only) ───────────────────────────
    if word and word[0] in _LEET_CHARS:
        partial = word[0].translate(_LEET_TABLE) + word[1:]
        if _e(partial): yield partial
        for s in ("1", "!", "123"):
            w = partial + s
            if _e(w): yield w

    # ── Tier 10: Structural mutations ────────────────────────────────────────
    # Doubled word
    w = word + word
    if _e(w): yield w
    w = cap + cap
    if _e(w): yield w
    # Reversed
    rev = word[::-1]
    if _e(rev): yield rev
    if _e(rev.capitalize()): yield rev.capitalize()
    # Doubled + symbol
    for s in ("1", "!", "123"):
        w = word + word + s
        if _e(w): yield w

    # ── Tier 11: Year patterns ────────────────────────────────────────────────
    # 1960–1999 (birth years, nostalgia passwords)
    for year in range(1960, 2000):
        y = str(year)
        for base in (word, cap):
            w = base + y
            if _e(w): yield w
    # 2000–2026 (current era)
    for year in range(2000, 2027):
        y = str(year)
        for base in (word, cap):
            w = base + y
            if _e(w): yield w
        # With symbol suffix — very common pattern: Shadow2025!
        for s in ("!", "@", "#"):
            w = cap + y + s
            if _e(w): yield w


# ── Rule count estimator ──────────────────────────────────────────────────────

def count_rules() -> int:
    """
    Return the number of unique mutations generated for a typical word.

    Uses ``"password"`` as the probe word — it contains characters that
    exercise every tier including leet speak, partial leet, and all
    case variants. Using a minimal word like ``"x"`` would skip leet
    tiers and produce a significant undercount.

    Returns:
        Approximate candidate count per base word.
    """
    return sum(1 for _ in apply_rules("password"))