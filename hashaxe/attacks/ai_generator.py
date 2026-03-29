# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/ai_generator.py
#  AI-powered candidate generation using GPT-2 with Markov chain fallback.
#  Generates passwords based on learned character patterns from training data.
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
AI generator attack mode — GPT-2 based candidate generation.

Uses a pre-trained HuggingFace GPT-2 model (124M parameters) to generate
password candidates based on learned character patterns. Falls back to
Markov chain generation if torch/transformers are not installed.

Dependencies (optional):
  - ``transformers`` — HuggingFace model hub
  - ``torch`` — PyTorch inference backend

Fallback: Built-in Markov chain generator (always available)
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)


class AIGeneratorAttack(BaseAttack):
    """AI-powered candidate generation using GPT-2 + Markov fallback.

    If transformers/torch are installed, uses GPT-2 to generate candidates.
    Otherwise, falls back to the built-in Markov chain generator trained
    on the provided wordlist.
    """

    attack_id   = "ai"
    attack_name = "AI Generator Attack"
    description = "GPT-2 neural candidate generation with Markov chain fallback."

    def __init__(self):
        self._model_manager = None

    def _has_ai_deps(self) -> bool:
        """Check if AI dependencies are available."""
        try:
            import torch  # type: ignore
            import transformers  # type: ignore
            return True
        except ImportError:
            return False

    def generate(self, config: AttackConfig) -> Iterator[str]:
        """Yield candidates in priority order:

        1. Wordlist entries (if ``-w`` was provided alongside ``--ai``)
        2. AI-generated candidates (GPT-2 or Markov fallback)

        This ensures that passing ``-w wordlist.txt --ai`` tests every
        wordlist entry first, then supplements with neural generation.
        """
        emitted = 0
        seen: set[str] = set()

        def _emit(candidate: str) -> bool:
            """Yield a candidate if unseen. Returns True if max reached."""
            nonlocal emitted
            if candidate in seen:
                return False
            seen.add(candidate)
            return True  # caller does the yield

        # ── Phase 1: Wordlist entries (highest priority) ─────────────────
        if config.wordlist:
            try:
                with open(config.wordlist, "r", encoding="utf-8", errors="replace") as wf:
                    for line in wf:
                        pw = line.rstrip("\n\r")
                        if not pw:
                            continue
                        if pw not in seen:
                            seen.add(pw)
                            yield pw
                            emitted += 1
                            if config.progress_callback:
                                config.progress_callback(emitted)
                            if config.max_candidates > 0 and emitted >= config.max_candidates:
                                return
            except OSError as exc:
                log.warning("Could not read wordlist %s: %s", config.wordlist, exc)

        # ── Phase 2: AI neural generation ────────────────────────────────
        if self._has_ai_deps():
            gen = self._generate_gpt2(config)
        else:
            log.info("AI deps not available. Falling back to Markov chain generator.")
            gen = self._generate_markov_fallback(config)

        for candidate in gen:
            if candidate in seen:
                continue
            seen.add(candidate)
            yield candidate
            emitted += 1
            if config.progress_callback:
                config.progress_callback(emitted)
            if config.max_candidates > 0 and emitted >= config.max_candidates:
                log.info("AI generator hit max_candidates=%d — stopping.", config.max_candidates)
                return

    def _generate_gpt2(self, config: AttackConfig) -> Iterator[str]:
        """Generate candidates using GPT-2 / DistilGPT-2 model.

        Generation order per seed word:
          1. The seed word itself (e.g. ``"password"``)
          2. Full GPT-2 completions (e.g. ``"password123"``)
          3. Stripped suffixes (e.g. ``"123"`` from ``"password123"``)

        On low-VRAM GPUs (<6GB), the ModelManager automatically routes to CPU.
        If CUDA OOM occurs during generation, we force a CPU reload and retry.
        """
        from hashaxe.ai.model_manager import ModelManager
        import torch

        # Password-appropriate generation length (not the config.max_length=64
        # which is meant for hash format max, not token generation depth).
        gen_max_tokens = min(config.max_length, 20)

        # CPU vs GPU batch sizing — CPU is ~100x slower, keep batches tiny
        if not torch.cuda.is_available():
            log.warning(
                "\033[1;33m[AI] CPU inference mode — generation will be slower "
                "than GPU but functional.\033[0m"
            )
            batch_num = 10
        else:
            batch_num = 50  # Conservative GPU batch to avoid OOM during generate()

        mgr = ModelManager()
        if not mgr.load():
            log.warning("Could not load AI model. Falling back to Markov.")
            yield from self._generate_markov_fallback(config)
            return

        # Use config-driven temperature/top_p, default to sensible values
        temperature = config.temperature if config.temperature > 0 else 1.2
        top_p = config.top_p if 0.0 < config.top_p <= 1.0 else 0.95

        # Set seed for reproducibility if provided
        if config.seed is not None:
            try:
                torch.manual_seed(config.seed)
            except Exception:
                pass

        # ── Generate in batches ──────────────────────────────────────────────
        seeds: list[str] = []
        if config.wordlist:
            try:
                # Read up to 50 seed words from the provided wordlist to use as AI prompts
                with open(config.wordlist, "r", encoding="utf-8", errors="ignore") as wf:
                    for line in wf:
                        pw = line.strip()
                        if pw and pw not in seeds:
                            seeds.append(pw)
                        if len(seeds) >= 50:
                            break
            except Exception as e:
                log.warning("Could not read seeds from wordlist: %s", e)

        # Fallback roots if no wordlist provided or wordlist was empty
        if not seeds:
            seeds = ["password", "admin", "secret", "letmein", "welcome",
                     "master", "dragon", "monkey", "shadow", "qwerty",
                     "123456", "iloveyou", "trustno1", "abc123", "sunshine"]

        oom_recovered = False

        # Phase 2a: Yield every seed word itself as a candidate FIRST.
        # Previously, seeds were only used as GPT-2 prompts and stripped
        # from output — meaning "password" could never be a candidate.
        for seed in seeds:
            yield seed

        # Phase 2b: GPT-2 neural completions
        for seed in seeds:
            candidates = mgr.generate(
                prompt=seed,
                num_candidates=batch_num,
                max_length=gen_max_tokens,
                temperature=temperature,
            )

            # CUDA OOM recovery: if a batch returns empty due to OOM,
            # force reload on CPU and retry this seed once.
            if not candidates and not oom_recovered and torch.cuda.is_available():
                log.warning("Empty batch from GPU — forcing CPU reload for stability")
                torch.cuda.empty_cache()
                mgr._pipeline = None  # Force reload
                mgr._force_cpu = True
                if mgr.load():
                    oom_recovered = True
                    batch_num = 10  # CPU-safe batch size
                    candidates = mgr.generate(
                        prompt=seed,
                        num_candidates=batch_num,
                        max_length=gen_max_tokens,
                        temperature=temperature,
                    )
                else:
                    log.warning("CPU reload failed. Falling back to Markov.")
                    yield from self._generate_markov_fallback(config)
                    return

            for candidate in candidates:
                # Yield full completion (e.g. "password123") AND
                # the stripped suffix (e.g. "123") — both are valid candidates
                if config.min_length <= len(candidate) <= config.max_length:
                    yield candidate

    def _generate_markov_fallback(self, config: AttackConfig) -> Iterator[str]:
        """Fallback: use Markov chain generator from attacks/markov.py."""
        if not config.wordlist:
            log.warning("No wordlist provided for Markov fallback. "
                       "AI mode requires either transformers+torch or a wordlist.")
            return

        from hashaxe.attacks.markov import MarkovAttack

        markov = MarkovAttack()
        markov_config = AttackConfig(
            wordlist=config.wordlist,
            markov_order=config.markov_order,
            min_length=config.min_length,
            max_length=config.max_length,
            seed=config.seed,
        )
        yield from markov.generate(markov_config)

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if self._has_ai_deps():
            return config.ai_candidates or 1000
        if config.wordlist:
            try:
                count = sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
                return count * 50  # Markov multiplier
            except OSError:
                return 0
        return 0

    def validate_config(self, config: AttackConfig) -> str | None:
        if not self._has_ai_deps() and not config.wordlist:
            return ("AI attack requires either: (1) transformers+torch installed, "
                    "or (2) --wordlist for Markov fallback")
        return None


_registry = AttackRegistry()
_registry.register(AIGeneratorAttack())
