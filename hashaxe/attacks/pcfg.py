# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/pcfg.py
#  PCFG attack mode — Probabilistic Context-Free Grammar password generation.
#  Learns password structures from training data and generates probability-ordered candidates.
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
PCFG attack mode — Probabilistic Context-Free Grammar password generation.

Learns password structure from a training wordlist by decomposing each password
into a grammar of base structures (e.g., L4D3S1 = 4 letters + 3 digits + 1 symbol).
Generates candidates in probability-descending order by combining the most
frequent structures with the most frequent terminal replacements.

This technique (Weir et al. 2009) consistently outperforms pure Markov chains
and brute-force approaches because it captures human password *structure*
patterns rather than just character-level transitions.

Architecture:
  1. TRAINING: Parse wordlist → extract base structures → count frequencies
  2. GENERATION: Walk structures by probability → fill terminals → yield candidates

References:
  - Matt Weir et al., "Password Cracking Using Probabilistic Context-Free Grammars"
    (IEEE Symposium on Security and Privacy, 2009)
"""
from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from itertools import product
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)

# ── Character class tokens ───────────────────────────────────────────────────

# Keyboard walk sequences (adjacent key patterns commonly seen in passwords)
_KEYBOARD_WALKS = frozenset(
    [
        # Alpha-only rows / diagonals (must contain ≥1 letter to avoid
        # reclassifying pure-digit runs away from D-class).
        "qwerty",
        "qwert",
        "asdf",
        "asdfg",
        "zxcv",
        "zxcvb",
        "qazwsx",
        "wsxedc",
        "edcrfv",
        "qaz",
        "wsx",
        "edc",
        "rfv",
        "1qaz",
        "2wsx",
        "3edc",
        "poiuy",
        "lkjhg",
        "mnbvc",
    ]
)

_CHAR_CLASSES = [
    ("D", re.compile(r"\d+")),  # Digit runs
    ("S", re.compile(r"[^\w\s]+")),  # Symbol runs
    ("U", re.compile(r"[A-Z]+")),  # Uppercase runs
    ("L", re.compile(r"[a-z]+")),  # Lowercase runs
]


def _tokenize(word: str) -> list[tuple[str, str]]:
    """Decompose a password into (class, value) token pairs.

    Example: 'Password123!' → [('U','P'), ('L','assword'), ('D','123'), ('S','!')]
    Keyboard walks detected: 'qwerty123' → [('K','qwerty'), ('D','123')]
    """
    tokens: list[tuple[str, str]] = []
    i = 0
    lower = word.lower()
    while i < len(word):
        # Check for keyboard-walk pattern first (longest match wins)
        kw_match = None
        for kw in sorted(_KEYBOARD_WALKS, key=len, reverse=True):
            if lower[i : i + len(kw)] == kw:
                kw_match = kw
                break
        if kw_match:
            tokens.append(("K", word[i : i + len(kw_match)]))
            i += len(kw_match)
            continue

        matched = False
        for cls_name, pattern in _CHAR_CLASSES:
            m = pattern.match(word, i)
            if m:
                tokens.append((cls_name, m.group()))
                i = m.end()
                matched = True
                break
        if not matched:
            # Catch-all for whitespace or other chars
            tokens.append(("S", word[i]))
            i += 1
    return tokens


def _structure_key(tokens: list[tuple[str, str]]) -> str:
    """Convert tokens to a structure key like 'U1L7D3S1'."""
    return "".join(f"{cls}{len(val)}" for cls, val in tokens)


class PCFGModel:
    """Probabilistic Context-Free Grammar model for password generation.

    Learns from a training wordlist by:
      1. Tokenizing each password into character-class segments
      2. Counting structure frequencies (e.g., L6D2 appears 15% of the time)
      3. Counting terminal frequencies per class+length
         (e.g., for D3: '123' = 30%, '456' = 5%, ...)
    """

    def __init__(self):
        self.structure_counts: Counter[str] = Counter()
        self.terminal_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._total_words = 0

    def train(self, wordlist_path: str, max_words: int = 500_000) -> int:
        """Train the PCFG model from a wordlist file.

        Returns the number of words processed.
        """
        count = 0
        try:
            with open(wordlist_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    word = line.rstrip("\n\r")
                    if not word or len(word) > 64:
                        continue

                    tokens = _tokenize(word)
                    if not tokens:
                        continue

                    structure = _structure_key(tokens)
                    self.structure_counts[structure] += 1

                    for cls, val in tokens:
                        key = f"{cls}{len(val)}"
                        self.terminal_counts[key][val] += 1

                    count += 1
                    if count >= max_words:
                        break
        except OSError as e:
            log.error("Cannot read wordlist for PCFG training: %s", e)
            return 0

        self._total_words = count
        log.info(
            "PCFG trained: %d words → %d unique structures, %d terminal groups",
            count,
            len(self.structure_counts),
            len(self.terminal_counts),
        )
        return count

    def generate(
        self,
        min_length: int = 1,
        max_length: int = 64,
        max_structures: int = 200,
        max_terminals_per_slot: int = 100,
    ) -> Iterator[str]:
        """Generate candidates in probability-descending order.

        Walks the most frequent structures, filling each slot with
        the most frequent terminals for that character class + length.
        """
        if not self.structure_counts:
            return

        # Get top structures by frequency
        top_structures = self.structure_counts.most_common(max_structures)

        for structure, _struct_count in top_structures:
            # Parse structure key into slots: 'U1L7D3S1K6' → [('U',1), ('L',7), ('D',3), ('S',1), ('K',6)]
            slots = re.findall(r"([DULSK])(\d+)", structure)
            if not slots:
                continue

            # For each slot, get the top terminals
            slot_terminals: list[list[str]] = []
            skip_structure = False
            for cls, length_str in slots:
                key = f"{cls}{length_str}"
                terminals = self.terminal_counts.get(key, Counter())
                if not terminals:
                    skip_structure = True
                    break
                top = [t for t, _ in terminals.most_common(max_terminals_per_slot)]
                slot_terminals.append(top)

            if skip_structure or not slot_terminals:
                continue

            # Generate Cartesian product of terminal replacements
            for combo in product(*slot_terminals):
                candidate = "".join(combo)
                if min_length <= len(candidate) <= max_length:
                    yield candidate

    @property
    def stats(self) -> dict:
        """Return model statistics."""
        return {
            "words_trained": self._total_words,
            "unique_structures": len(self.structure_counts),
            "terminal_groups": len(self.terminal_counts),
            "top_5_structures": self.structure_counts.most_common(5),
        }


class PCFGAttack(BaseAttack):
    """PCFG-based password candidate generation.

    Learns human password structure patterns from a training wordlist
    and generates candidates in probability-descending order.
    Significantly outperforms brute-force and basic Markov approaches.
    """

    attack_id = "pcfg"
    attack_name = "PCFG Grammar Attack"
    description = (
        "Probabilistic Context-Free Grammar attack. Learns password structure "
        "patterns (letter/digit/symbol segments) from a training wordlist and "
        "generates candidates in probability order."
    )

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist:
            return

        model = PCFGModel()
        trained = model.train(config.wordlist)
        if trained == 0:
            log.warning("PCFG training failed — no words processed")
            return

        stats = model.stats
        log.info(
            "PCFG model: %d words → %d structures. Top: %s",
            stats["words_trained"],
            stats["unique_structures"],
            ", ".join(f"{s}({c})" for s, c in stats["top_5_structures"]),
        )

        seen: set[str] = set()
        for candidate in model.generate(
            min_length=config.min_length,
            max_length=config.max_length,
        ):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.wordlist:
            return 0
        try:
            count = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
            return count * 200  # PCFG generates ~200x expansion
        except OSError:
            return 0

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "PCFG attack requires --wordlist as training corpus"
        return None


# Auto-register
_registry = AttackRegistry()
_registry.register(PCFGAttack())
