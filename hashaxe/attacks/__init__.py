# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/__init__.py
#  Advanced attack mode plugin system with auto-discovery registry.
#  Supports wordlist, mask, PRINCE, Markov, hybrid, PCFG, AI, and OSINT attacks.
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
hashaxe.attacks — Advanced attack mode plugin system.

Architecture:
  Every attack mode is a subclass of ``BaseAttack`` that provides:
    • ``generate(config)``        → yields candidate passwords
    • ``estimate_keyspace()``     → total number of possible candidates
    • ``name`` / ``description``  → human-readable metadata

  ``AttackRegistry`` auto-discovers all installed attack plugins.

Attack Modes:
  • wordlist    — Streaming wordlist with optional rules
  • mask        — Character-position mask generation
  • combinator  — Cartesian product of two wordlists
  • prince      — PRINCE probability-ordered chaining
  • markov      — Character-level Markov chain generation
  • hybrid      — Wordlist + mask combination
  • policy      — Policy-constrained candidate generation

Developed by Bhanu Guragain · GANGA Offensive Ops
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── Attack configuration ──────────────────────────────────────────────────────


@dataclass
class AttackConfig:
    """Configuration passed to attack generators.

    Attributes:
        wordlist:           Primary wordlist path
        wordlist2:          Secondary wordlist (combinator mode)
        mask:               Mask pattern (e.g. ?u?l?l?l?d?d)
        custom_charsets:    Custom charset definitions
        rules:              Rule mutations to apply
        min_length:         Minimum candidate length
        max_length:         Maximum candidate length
        policy:             Policy constraint string
        markov_order:       Markov chain order (2–4)
        prince_min_elems:   PRINCE minimum chain elements
        prince_max_elems:   PRINCE maximum chain elements
        ai_candidates:      Number of AI-generated candidates
        max_candidates:     Rate limit — 0 = unlimited
        checkpoint_file:    Path to save/resume checkpoint state
        progress_callback:  Callable invoked with candidates-generated count
        temperature:        AI model sampling temperature (higher = more diverse)
        top_p:              Nucleus sampling cutoff (0.0–1.0)
        seed:               RNG seed for deterministic generation
        markov_smoothing_k: Laplace smoothing constant for Markov model
    """

    wordlist: str | None = None
    wordlist2: str | None = None
    mask: str | None = None
    custom_charsets: dict[str, str] = field(default_factory=dict)
    rules: list | None = None
    min_length: int = 1
    max_length: int = 64
    policy: str | None = None
    markov_order: int = 3
    prince_min_elems: int = 1
    prince_max_elems: int = 8
    ai_candidates: int = 1000
    # ── V4 Audit additions ────────────────────────────────────────────────
    max_candidates: int = 0
    checkpoint_file: str | None = None
    progress_callback: Callable[[int], None] | None = None
    temperature: float = 1.0
    top_p: float = 1.0
    seed: int | None = None
    markov_smoothing_k: float = 0.0


# ── Base attack ABC ──────────────────────────────────────────────────────────


class BaseAttack(ABC):
    """Abstract base class for all attack mode plugins."""

    attack_id: str = ""  # e.g. "wordlist", "combinator", "prince"
    attack_name: str = ""  # e.g. "Wordlist Attack"
    description: str = ""  # Brief description

    @abstractmethod
    def generate(self, config: AttackConfig) -> Iterator[str]:
        """Yield candidate passwords.

        This is the core generator. Must be memory-efficient —
        yield one candidate at a time, never buffer the full keyspace.
        """
        ...

    @abstractmethod
    def estimate_keyspace(self, config: AttackConfig) -> int:
        """Estimate total number of candidates this attack will produce.

        Used for ETA calculation and progress display.
        Returns 0 if estimation is not possible.
        """
        ...

    def validate_config(self, config: AttackConfig) -> str | None:
        """Validate configuration. Return error message or None if valid."""
        return None


# ── Attack registry ──────────────────────────────────────────────────────────


class AttackRegistry:
    """Central registry of all available attack mode plugins."""

    _instance: AttackRegistry | None = None
    _attacks: dict[str, BaseAttack]

    def __new__(cls) -> AttackRegistry:
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._attacks = {}
            inst._discovered = False
            cls._instance = inst
        return cls._instance

    def register(self, attack: BaseAttack) -> None:
        aid = attack.attack_id
        if not aid:
            raise ValueError(f"Attack {attack.__class__.__name__} has empty attack_id")
        self._attacks[aid] = attack
        logger.debug("Registered attack: %s (%s)", aid, attack.attack_name)

    def discover(self) -> None:
        if self._discovered:
            return
        self._discovered = True

        import hashaxe.attacks as pkg

        pkg_path = Path(pkg.__file__).parent
        for info in pkgutil.iter_modules([str(pkg_path)]):
            if info.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"hashaxe.attacks.{info.name}")
            except Exception:
                logger.warning("Failed to import attack: %s", info.name, exc_info=True)

    def get(self, attack_id: str) -> BaseAttack | None:
        self.discover()
        return self._attacks.get(attack_id)

    def all_attacks(self) -> list[BaseAttack]:
        self.discover()
        return list(self._attacks.values())

    def list_ids(self) -> list[str]:
        self.discover()
        return sorted(self._attacks.keys())

    def reset(self) -> None:
        self._attacks.clear()
        self._discovered = False

    def __contains__(self, attack_id: str) -> bool:
        self.discover()
        return attack_id in self._attacks

    def __len__(self) -> int:
        self.discover()
        return len(self._attacks)


__all__ = [
    "AttackConfig",
    "AttackRegistry",
    "BaseAttack",
]
