# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/hybrid.py
#  Hybrid attack mode — Wordlist + Mask combination attack.
#  Appends or prepends mask-generated suffixes/prefixes to each wordlist entry.
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
Hybrid attack mode — Wordlist + Mask combination.

For each word in the wordlist, append (or prepend) all mask-generated
suffixes/prefixes:
  word + mask_candidate  (append mode, default)
  mask_candidate + word  (prepend mode)

Example: wordlist=["pass"], mask="?d?d?d" → pass000, pass001, ..., pass999
"""
from __future__ import annotations

import logging
import string
from collections.abc import Iterator
from itertools import product
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)

_BUILTINS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\",
    "?a": string.printable.strip(),
}


def _parse_mask(mask: str, custom: dict[str, str] | None = None) -> list[str]:
    if custom is None:
        custom = {}
    charsets: list[str] = []
    i = 0
    while i < len(mask):
        if i + 1 < len(mask) and mask[i] == "?":
            token = mask[i:i + 2]
            if token in _BUILTINS:
                charsets.append(_BUILTINS[token])
            elif token in custom:
                charsets.append(custom[token])
            else:
                charsets.append(token[1])
            i += 2
        else:
            charsets.append(mask[i])
            i += 1
    return charsets


class HybridAttack(BaseAttack):
    """Wordlist + mask hybrid: append mask-generated suffixes to each word."""

    attack_id   = "hybrid"
    attack_name = "Hybrid Attack"
    description = "For each word in wordlist, append all mask-generated suffixes (word + ?d?d?d)."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist or not config.mask:
            return

        charsets = _parse_mask(config.mask, config.custom_charsets)

        try:
            with open(config.wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    word = line.rstrip("\n\r")
                    if not word:
                        continue

                    for combo in product(*charsets):
                        suffix = "".join(combo)
                        candidate = word + suffix
                        if config.min_length <= len(candidate) <= config.max_length:
                            yield candidate
        except OSError as e:
            log.error("Cannot read wordlist: %s", e)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.wordlist or not config.mask:
            return 0
        try:
            word_count = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
        except OSError:
            return 0

        charsets = _parse_mask(config.mask, config.custom_charsets)
        mask_space = 1
        for cs in charsets:
            mask_space *= len(cs)
        return word_count * mask_space

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "Hybrid attack requires --wordlist"
        if not config.mask:
            return "Hybrid attack requires --mask"
        return None


_registry = AttackRegistry()
_registry.register(HybridAttack())
