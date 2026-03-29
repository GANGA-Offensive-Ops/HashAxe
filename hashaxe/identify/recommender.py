# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/recommender.py
#  Context-Aware Attack Recommender for optimal strategy selection.
#  Recommends attack mode, wordlist, rules, GPU/CPU, and time estimate.
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
hashaxe.identify.recommender — Context-Aware Attack Recommender.

Given a classified hash, recommends the optimal attack strategy:
  - Attack mode (wordlist, rules, mask, hybrid, combinator)
  - Wordlist selection (size-appropriate for difficulty)
  - Rule selection (best64, dive, toggles)
  - GPU vs CPU recommendation
  - Estimated time to hashaxe
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class AttackPlan:
    """Recommended attack plan for a hash target."""
    hash_type: str
    hashcat_mode: int | None
    phases: list[AttackPhase] = field(default_factory=list)
    total_estimated_time: str = "unknown"
    gpu_recommended: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class AttackPhase:
    """Single phase of an attack plan."""
    phase_name: str
    attack_mode: str  # wordlist, mask, hybrid, rules, combinator
    command: str  # Exact hashaxe / hashcat command
    estimated_time: str
    success_probability: str  # high, medium, low


# ── Phase templates by difficulty ─────────────────────────────────────────────

def recommend(hash_type: str, hashcat_mode: int | None = None,
              difficulty: str = "unknown") -> AttackPlan:
    """Generate a multi-phase attack plan based on hash difficulty."""
    plan = AttackPlan(
        hash_type=hash_type,
        hashcat_mode=hashcat_mode,
    )

    if difficulty in ("TRIVIAL", "FAST"):
        plan.phases = [
            AttackPhase(
                phase_name="Phase 1: Quick Wordlist",
                attack_mode="wordlist",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w rockyou.txt hash.txt",
                estimated_time="< 1 minute",
                success_probability="high",
            ),
            AttackPhase(
                phase_name="Phase 2: Rules Attack",
                attack_mode="rules",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w rockyou.txt -r best64.rule hash.txt",
                estimated_time="~5 minutes",
                success_probability="high",
            ),
            AttackPhase(
                phase_name="Phase 3: Mask Brute Force",
                attack_mode="mask",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -a mask '?a?a?a?a?a?a?a?a' hash.txt",
                estimated_time="~30 minutes (8 chars)",
                success_probability="medium",
            ),
        ]
        plan.total_estimated_time = "< 1 hour"
        plan.gpu_recommended = False

    elif difficulty == "MEDIUM":
        plan.phases = [
            AttackPhase(
                phase_name="Phase 1: Targeted Wordlist",
                attack_mode="wordlist",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w rockyou.txt hash.txt",
                estimated_time="~10 minutes",
                success_probability="medium",
            ),
            AttackPhase(
                phase_name="Phase 2: Light Rules",
                attack_mode="rules",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w rockyou.txt -r best64.rule hash.txt",
                estimated_time="~1 hour",
                success_probability="medium",
            ),
        ]
        plan.total_estimated_time = "~1-2 hours"
        plan.gpu_recommended = True
        plan.notes.append("GPU recommended for reasonable speed")

    elif difficulty in ("SLOW", "EXTREME"):
        plan.phases = [
            AttackPhase(
                phase_name="Phase 1: Small Targeted Wordlist",
                attack_mode="wordlist",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w top1000.txt hash.txt",
                estimated_time="~30 minutes",
                success_probability="low",
            ),
            AttackPhase(
                phase_name="Phase 2: OSINT-Generated Wordlist",
                attack_mode="wordlist",
                command=f"hashaxe hashaxe -m {hashcat_mode or 0} -w osint_generated.txt hash.txt",
                estimated_time="~1 hour",
                success_probability="medium",
            ),
        ]
        plan.total_estimated_time = "hours to days"
        plan.gpu_recommended = True
        plan.notes.append("GPU REQUIRED — CPU is infeasible")
        plan.notes.append("Consider OSINT profiling for targeted wordlist generation")

    else:
        plan.notes.append("Unknown difficulty — apply standard rockyou attack")

    return plan


def recommend_from_classification(classification) -> AttackPlan:
    """Generate plan from a ClassifiedHash object."""
    return recommend(
        hash_type=classification.format_id,
        hashcat_mode=classification.hashcat_mode,
        difficulty=classification.difficulty,
    )
