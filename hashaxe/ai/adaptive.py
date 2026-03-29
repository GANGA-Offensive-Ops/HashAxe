# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/ai/adaptive.py
#  Adaptive AI temperature and sampling controller with RL-inspired feedback loop.
#  Dynamically adjusts temperature, top_k, top_p based on hit rate during cracking.
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
hashaxe.ai.adaptive — Adaptive AI temperature and sampling controller.

Implements a Reinforcement Learning-inspired feedback loop that dynamically
adjusts the AI model's sampling parameters (temperature, top_k, top_p) based
on the observed hit rate during a cracking session.

Algorithm (simplified RL):
  - Track: candidates_generated, candidates_matched (successful cracks)
  - hit_rate = matched / generated
  - If hit_rate is HIGH → reduce temperature (exploit known patterns)
  - If hit_rate is LOW  → increase temperature (explore more diverse candidates)
  - Clamp values within safe bounds to prevent degenerate generation

This is designed to work as a wrapper around ModelManager.generate(),
providing a feedback-driven candidate stream.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveConfig:
    """Live-tunable sampling parameters with RL feedback bounds."""

    temperature: float = 1.2
    top_k: int = 50
    top_p: float = 0.95

    # RL bounds
    temp_min: float = 0.6
    temp_max: float = 2.0
    top_k_min: int = 10
    top_k_max: int = 200

    # Feedback tracking
    candidates_generated: int = 0
    candidates_matched: int = 0
    adjustment_interval: int = 500  # adjust after every N candidates
    _last_adjustment: int = 0

    @property
    def hit_rate(self) -> float:
        """Current hit rate (matched / generated)."""
        if self.candidates_generated == 0:
            return 0.0
        return self.candidates_matched / self.candidates_generated

    def record_generated(self, count: int = 1) -> None:
        """Record that candidates were generated."""
        self.candidates_generated += count

    def record_match(self, count: int = 1) -> None:
        """Record successful password matches."""
        self.candidates_matched += count

    def should_adjust(self) -> bool:
        """Check if it's time for a parameter adjustment."""
        return self.candidates_generated - self._last_adjustment >= self.adjustment_interval

    def adjust(self) -> dict[str, float]:
        """Perform RL-inspired parameter adjustment.

        Returns a dict of changes made for logging.
        """
        self._last_adjustment = self.candidates_generated
        changes: dict[str, float] = {}
        rate = self.hit_rate

        if rate > 0.01:
            # High hit rate → exploit: lower temperature, tighter sampling
            old_temp = self.temperature
            self.temperature = max(self.temp_min, self.temperature * 0.95)
            self.top_k = max(self.top_k_min, self.top_k - 5)
            changes["temperature"] = self.temperature - old_temp
            changes["action"] = "exploit"
        elif rate < 0.001 and self.candidates_generated > 1000:
            # Low hit rate → explore: higher temperature, wider sampling
            old_temp = self.temperature
            self.temperature = min(self.temp_max, self.temperature * 1.05)
            self.top_k = min(self.top_k_max, self.top_k + 10)
            changes["temperature"] = self.temperature - old_temp
            changes["action"] = "explore"
        else:
            changes["action"] = "hold"

        if changes.get("action") != "hold":
            logger.debug(
                "Adaptive AI: %s (temp=%.2f, top_k=%d, rate=%.4f)",
                changes["action"],
                self.temperature,
                self.top_k,
                rate,
            )

        return changes

    def snapshot(self) -> dict:
        """Return current state snapshot for logging/display."""
        return {
            "temperature": round(self.temperature, 3),
            "top_k": self.top_k,
            "top_p": self.top_p,
            "hit_rate": round(self.hit_rate, 6),
            "generated": self.candidates_generated,
            "matched": self.candidates_matched,
        }
