# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/prince.py
#  PRINCE attack mode — Probability Ranked INterleaving of Characters and Elements.
#  Chains wordlist elements by length-ordered probability for compound password attacks.
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
PRINCE attack mode — Probability Ranked INterleaving of Characters and Elements.

Algorithm:
  1. Load wordlist and sort by word length
  2. Group words by length into buckets
  3. Build chains of 1→N elements, shortest first
  4. Yield combined chains ordered by total length (probability)

This is a highly effective attack for compound passwords like
"super123", "admin2024", "passwordreset" etc.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterator
from itertools import product
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)


class PrinceAttack(BaseAttack):
    """PRINCE algorithm — chain wordlist elements by length-ordered probability."""

    attack_id   = "prince"
    attack_name = "PRINCE Attack"
    description = "Probability-ordered chaining of wordlist elements (1→N words combined)."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist:
            return

        min_elems = config.prince_min_elems
        max_elems = config.prince_max_elems

        # Load words grouped by length
        buckets: dict[int, list[str]] = defaultdict(list)
        try:
            with open(config.wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    word = line.rstrip("\n\r")
                    if word:
                        buckets[len(word)].append(word)
        except OSError as e:
            log.error("Cannot read wordlist: %s", e)
            return

        if not buckets:
            return

        lengths = sorted(buckets.keys())
        all_words = []
        for l in lengths:
            all_words.extend(buckets[l])

        # Deduplication set to prevent yielding duplicate candidates
        seen: set[str] = set()
        emitted = 0

        # Generate chains of increasing element count
        for num_elems in range(min_elems, max_elems + 1):
            if num_elems == 1:
                # Single words — sorted by length (shortest first)
                for word in all_words:
                    if config.min_length <= len(word) <= config.max_length:
                        if word not in seen:
                            seen.add(word)
                            yield word
                            emitted += 1
                            if config.progress_callback:
                                config.progress_callback(emitted)
                            if config.max_candidates > 0 and emitted >= config.max_candidates:
                                return
            else:
                # Multi-element chains
                for combo in product(all_words, repeat=num_elems):
                    candidate = "".join(combo)
                    if config.min_length <= len(candidate) <= config.max_length:
                        if candidate not in seen:
                            seen.add(candidate)
                            yield candidate
                            emitted += 1
                            if config.progress_callback:
                                config.progress_callback(emitted)
                            if config.max_candidates > 0 and emitted >= config.max_candidates:
                                return

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.wordlist:
            return 0
        try:
            count = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
        except OSError:
            return 0

        total = 0
        for n in range(config.prince_min_elems, config.prince_max_elems + 1):
            total += count ** n
        return total

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "PRINCE attack requires --wordlist"
        return None


_registry = AttackRegistry()
_registry.register(PrinceAttack())
