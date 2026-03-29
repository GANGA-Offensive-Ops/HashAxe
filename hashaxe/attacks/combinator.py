# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/combinator.py
#  Combinator attack mode — Cartesian product of two wordlists.
#  Combines every word from wordlist A with every word from wordlist B.
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
Combinator attack mode — Cartesian product of two wordlists.

For every word_A in wordlist1 and word_B in wordlist2:
  yield word_A + word_B
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)


class CombinatorAttack(BaseAttack):
    """Combine every word from wordlist A with every word from wordlist B."""

    attack_id   = "combinator"
    attack_name = "Combinator Attack"
    description = "Cartesian product: word_A + word_B from two wordlists."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.wordlist or not config.wordlist2:
            return

        import os
        
        # CPU-Mem Protection (Fallback): 
        # Only cache wordlist2 into RAM if it is less than 500MB.
        # Otherwise, stream it dynamically to prevent Out-Of-Memory host crashes.
        cache_limit = 500 *  1024 * 1024  # 500 MB
        use_cache = False
        words_b = []
        try:
            if os.path.getsize(config.wordlist2) <= cache_limit:
                use_cache = True
                with open(config.wordlist2, encoding="utf-8", errors="replace") as f:
                    words_b = [line.rstrip("\n\r") for line in f if line.strip()]
            else:
                log.warning("[CPU-MEMORY PROTECT] Wordlist 2 exceeds 500MB! Streaming from disk natively to prevent Python OOM crashes.")
        except OSError as e:
            log.error("Cannot query wordlist2: %s", e)
            return

        try:
            with open(config.wordlist, encoding="utf-8", errors="replace") as f_a:
                for line_a in f_a:
                    word_a = line_a.rstrip("\n\r")
                    if not word_a:
                        continue
                        
                    if use_cache:
                        # High-speed list iteration
                        for word_b in words_b:
                            candidate = word_a + word_b
                            if config.min_length <= len(candidate) <= config.max_length:
                                yield candidate
                    else:
                        # Memory-safe file stream iteration (slower natively)
                        with open(config.wordlist2, encoding="utf-8", errors="replace") as f_b:
                            for line_b in f_b:
                                word_b = line_b.rstrip("\n\r")
                                if not word_b: continue
                                candidate = word_a + word_b
                                if config.min_length <= len(candidate) <= config.max_length:
                                    yield candidate
                                    
        except OSError as e:
            log.error("Cannot read wordlist: %s", e)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.wordlist or not config.wordlist2:
            return 0
        try:
            count_a = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
            count_b = sum(1 for line in open(config.wordlist2, errors="replace") if line.strip())
            return count_a * count_b
        except OSError:
            return 0

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.wordlist:
            return "Combinator attack requires --wordlist"
        if not config.wordlist2:
            return "Combinator attack requires --wordlist2"
        return None


_registry = AttackRegistry()
_registry.register(CombinatorAttack())
