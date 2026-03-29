# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/wordlist.py
#  Wordlist attack mode — streaming dictionary attack with optional rule mutations.
#  Standard dictionary attack streaming candidates from wordlist files.
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
Wordlist attack mode — streaming wordlist with optional rule mutations.

Wraps the existing WordlistStreamer for the new attack plugin system.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)


class WordlistAttack(BaseAttack):
    """Standard dictionary attack — stream passwords from a wordlist file."""

    attack_id = "wordlist"
    attack_name = "Wordlist Attack"
    description = "Stream candidates from a wordlist file, optionally applying rule mutations."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist:
            return

        try:
            with open(config.wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    candidate = line.rstrip("\n\r")
                    if not candidate:
                        continue
                    if config.min_length <= len(candidate) <= config.max_length:
                        yield candidate
        except OSError as e:
            log.error("Wordlist read error: %s", e)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.wordlist:
            return 0
        try:
            count = 0
            with open(config.wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        count += 1
            return count
        except OSError:
            return 0

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "Wordlist attack requires --wordlist/-w"
        return None


_registry = AttackRegistry()
_registry.register(WordlistAttack())
