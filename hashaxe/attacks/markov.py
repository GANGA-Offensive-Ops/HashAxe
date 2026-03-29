# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/markov.py
#  Markov chain attack mode — character-level statistical password generation.
#  Builds transition probability matrix from wordlist for probability-ordered candidates.
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
Markov chain attack mode — character-level statistical generation.

Builds a transition probability matrix from a wordlist and generates
candidates in probability-descending order.

Order determines look-back:
  order=2: P(c3 | c1,c2) — bigram context
  order=3: P(c4 | c1,c2,c3) — trigram context (recommended)
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Iterator
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)

_START = "\x02"  # Start-of-word sentinel
_END = "\x03"  # End-of-word sentinel


class MarkovAttack(BaseAttack):
    """Character-level Markov chain password generator."""

    attack_id = "markov"
    attack_name = "Markov Chain Attack"
    description = "Generate candidates using character-level Markov chains built from a wordlist."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist:
            return

        order = config.markov_order
        smoothing_k = config.markov_smoothing_k
        transitions = self._build_model(config.wordlist, order)

        if not transitions:
            return

        # Pre-compute vocabulary for smoothing
        vocab: set[str] = set()
        for nxt_map in transitions.values():
            vocab.update(nxt_map.keys())
        vocab_size = max(len(vocab), 1)

        emitted = 0

        # Iterative DFS-based generation to prevent stack overflow
        start_ctx = _START * order
        # stack stores: (context, word, depth, char_iter)
        stack = [(start_ctx, "", 0, None)]

        while stack:
            context, word, depth, char_iter = stack[-1]

            if char_iter is None:
                if depth > config.max_length:
                    stack.pop()
                    continue

                next_chars = transitions.get(context, {})
                if not next_chars:
                    if len(word) >= config.min_length:
                        yield word
                        emitted += 1
                        if config.progress_callback:
                            config.progress_callback(emitted)
                        if config.max_candidates > 0 and emitted >= config.max_candidates:
                            return
                    stack.pop()
                    continue

                # Apply Add-k smoothing: P(c|ctx) = (count(c) + k) / (total + k*V)
                if smoothing_k > 0:
                    total = sum(next_chars.values())
                    smoothed = {
                        c: (cnt + smoothing_k) / (total + smoothing_k * vocab_size)
                        for c, cnt in next_chars.items()
                    }
                    # Sort by smoothed probability (most probable first)
                    sorted_chars = sorted(smoothed.items(), key=lambda x: -x[1])
                else:
                    # Sort by frequency (most probable first)
                    sorted_chars = sorted(next_chars.items(), key=lambda x: -x[1])

                char_iter = iter(sorted_chars)
                stack[-1] = (context, word, depth, char_iter)

            try:
                char, _score = next(char_iter)
                if char == _END:
                    if len(word) >= config.min_length:
                        yield word
                        emitted += 1
                        if config.progress_callback:
                            config.progress_callback(emitted)
                        if config.max_candidates > 0 and emitted >= config.max_candidates:
                            return
                else:
                    new_context = (context + char)[-order:]
                    stack.append((new_context, word + char, depth + 1, None))
            except StopIteration:
                stack.pop()

    def _build_model(self, wordlist_path: str, order: int) -> dict[str, dict[str, int]]:
        """Build Markov transition model from wordlist."""
        transitions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        try:
            with open(wordlist_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    word = line.rstrip("\n\r")
                    if not word:
                        continue

                    # Pad with sentinels
                    padded = _START * order + word + _END

                    for i in range(len(padded) - order):
                        context = padded[i : i + order]
                        next_char = padded[i + order]
                        transitions[context][next_char] += 1
        except OSError as e:
            log.error("Cannot read wordlist for Markov model: %s", e)
            return {}

        return dict(transitions)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        # Exact keyspace is hard to predict for Markov chains
        # Return approximate based on wordlist size × branching factor
        if not config.wordlist:
            return 0
        try:
            count = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
            return count * 50  # rough multiplier
        except OSError:
            return 0

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "Markov attack requires --wordlist to build transition model"
        if config.markov_order < 1 or config.markov_order > 6:
            return "Markov order must be 1–6"
        return None


_registry = AttackRegistry()
_registry.register(MarkovAttack())
