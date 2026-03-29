# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/mask.py
#  Mask attack mode — generate candidates from character position masks.
#  Supports ?l/?u/?d/?s/?a placeholders and custom charsets for targeted attacks.
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
Mask attack mode — generate candidates from character position masks.

Wraps the existing MaskEngine for the new attack plugin system.

Mask notation:
  ?l = lowercase a-z
  ?u = uppercase A-Z
  ?d = digits 0-9
  ?s = symbols
  ?a = all printable ASCII
  ?1-?4 = custom charsets
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


def _parse_mask(mask: str, custom: dict[str, str] = {}) -> list[str]:
    """Parse mask into list of charset strings per position."""
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
                charsets.append(token[1])  # literal character
            i += 2
        else:
            charsets.append(mask[i])
            i += 1
    return charsets


class MaskAttack(BaseAttack):
    """Mask-based brute-force attack — generate all combinations for each position."""

    attack_id   = "mask"
    attack_name = "Mask Attack"
    description = "Generate candidates from character position masks (?l?u?d?s?a)."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.mask:
            return
        charsets = _parse_mask(config.mask, config.custom_charsets)
        for combo in product(*charsets):
            yield "".join(combo)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.mask:
            return 0
        charsets = _parse_mask(config.mask, config.custom_charsets)
        total = 1
        for cs in charsets:
            total *= len(cs)
        return total

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.mask:
            return "Mask attack requires --mask"
        return None


_registry = AttackRegistry()
_registry.register(MaskAttack())
