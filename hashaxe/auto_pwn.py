# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/auto_pwn.py
#  Intelligent Attack Orchestrator (Auto-Pwn) for automated cracking pipeline.
#  Detects hash complexity, benchmarks hardware, and executes staged attacks.
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
hashaxe.auto_pwn — Intelligent Attack Orchestrator (Auto-Pwn).

Automatically orchestrates the optimum cracking pipeline for a given target.
Instead of requiring manual attack selection, AutoPwn:
  1. Detects the hash complexity and benchmarks hardware speed.
  2. Executes Stage 1: Fast/Small Wordlist (e.g., top 100k, rockyou_small).
  3. Executes Stage 2: Target-specific OSINT profiling (if provided).
  4. Executes Stage 3: AI/PCFG generation based on target complexity.
  5. Executes Stage 4: Intensive masking and rules on remaining hashes.
  6. Falls back to Distributed Brute Force for mathematically feasible gaps.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from hashaxe.cracker import hashaxe

logger = logging.getLogger(__name__)


class AutoPwnOrchestrator:
    """Intelligent cracking pipeline manager.

    Usage:
        orchestrator = AutoPwnOrchestrator(key_path, wordlist_path)
        result = orchestrator.execute_pipeline()
    """

    def __init__(
        self,
        key_path: str,
        wordlist_path: str,
        osint_path: str | None = None,
        max_duration_sec: int = 3600,
        threads: int = 0,
        raw_hash: str | None = None,
    ):
        self.key_path = key_path
        self.wordlist_path = wordlist_path
        self.osint_path = osint_path
        self.max_duration = max_duration_sec
        self.threads = threads
        self.start_time = 0.0
        
        if raw_hash:
            from hashaxe.core.normalization import normalize_hash_string
            self.raw_hash = normalize_hash_string(raw_hash).clean_hash
        else:
            self.raw_hash = None

    def _time_remaining(self) -> float:
        return max(0.0, self.max_duration - (time.time() - self.start_time))

    def execute_pipeline(self) -> str | None:
        """Run the full Auto-Pwn orchestration pipeline."""
        self.start_time = time.time()
        logger.info("Starting Auto-Pwn Orchestration Pipeline")

        # Hardware profiling — detect available accelerators
        self._has_gpu = False
        try:
            from hashaxe.gpu.accelerator import detect_gpu

            gpu = detect_gpu()
            if gpu:
                self._has_gpu = True
                logger.info(f"[Auto-Pwn] GPU detected: {gpu.name} — enabling GPU stages")
        except Exception:
            pass
        logger.info(
            f"[Auto-Pwn] Hardware profile: GPU={'YES' if self._has_gpu else 'NO'}, "
            f"Threads={self.threads or 'auto'}"
        )

        # STAGE 1: Quick Wins (Wordlist + Fast Rules)
        logger.info("[Auto-Pwn] Stage 1: Fast Wordlist Attack")
        result = self._stage_fast_wordlist()
        if result:
            return result
        if self._time_remaining() <= 0:
            return None

        # STAGE 2: OSINT Profiling
        if self.osint_path:
            logger.info(f"[Auto-Pwn] Stage 2: Targeted OSINT Profiling ({self.osint_path})")
            result = self._stage_osint()
            if result:
                return result
            if self._time_remaining() <= 0:
                return None

        # STAGE 3: AI / PCFG Generation
        logger.info("[Auto-Pwn] Stage 3: PCFG Grammar Attack")
        result = self._stage_smart_ai()
        if result:
            return result
        if self._time_remaining() <= 0:
            return None

        # STAGE 4: Heavy Rules & Masking
        logger.info("[Auto-Pwn] Stage 4: Heavy Ruleset")
        result = self._stage_heavy_rules()
        if result:
            return result

        logger.warning("[Auto-Pwn] Pipeline exhausted. Target not cracked.")
        return None

    def _stage_fast_wordlist(self) -> str | None:
        return hashaxe(
            key_path=self.key_path,
            raw_hash=self.raw_hash,
            wordlist=self.wordlist_path,
            threads=self.threads,
            attack_mode_override="wordlist",
            quiet=True,
        )

    def _stage_osint(self) -> str | None:
        return hashaxe(
            key_path=self.key_path,
            raw_hash=self.raw_hash,
            wordlist=str(self.osint_path),  # Acts as base list
            threads=self.threads,
            attack_mode_override="osint",
            quiet=True,
        )

    def _stage_smart_ai(self) -> str | None:
        try:
            return hashaxe(
                key_path=self.key_path,
                raw_hash=self.raw_hash,
                wordlist=self.wordlist_path,
                threads=self.threads,
                attack_mode_override="ai",
                quiet=True,
            )
        except SystemExit:
            return None

    def _stage_heavy_rules(self) -> str | None:
        return hashaxe(
            key_path=self.key_path,
            raw_hash=self.raw_hash,
            wordlist=self.wordlist_path,
            threads=self.threads,
            use_rules=True,
            attack_mode_override="wordlist",
            quiet=True,
        )
