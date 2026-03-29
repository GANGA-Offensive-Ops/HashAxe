# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/estimator.py
#  GPU/CPU Time Estimator for cracking time predictions.
#  Uses hash algorithm, hardware profile, and keyspace for realistic estimates.
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
hashaxe.identify.estimator — GPU/CPU Time Estimator.

Estimates cracking time based on hash algorithm, hardware profile,
and keyspace size. Provides realistic time estimates for attack planning.

Hardware profiles derived from published hashcat benchmarks.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class TimeEstimate:
    """Estimated cracking time for a given configuration."""
    format_id: str
    hardware: str
    keyspace_size: int
    hashes_per_second: float
    estimated_seconds: float
    estimated_human: str
    feasible: bool


# ── Benchmark database: hashes/second per hardware tier ───────────────────────
# Source: hashcat benchmarks on common hardware (order-of-magnitude estimates)

_BENCHMARKS: dict[str, dict[str, float]] = {
    # format_id → { hardware_tier: hashes/sec }
    "hash.md5":          {"cpu": 5e8,  "gpu_mid": 2e10, "gpu_high": 6.5e10},
    "hash.sha1":         {"cpu": 2e8,  "gpu_mid": 1e10, "gpu_high": 3.5e10},
    "hash.sha256":       {"cpu": 1e8,  "gpu_mid": 4e9,  "gpu_high": 1.5e10},
    "hash.sha512":       {"cpu": 5e7,  "gpu_mid": 1.5e9, "gpu_high": 5e9},
    "hash.md5crypt":     {"cpu": 1e5,  "gpu_mid": 2e7,  "gpu_high": 7e7},
    "hash.sha256crypt":  {"cpu": 5e4,  "gpu_mid": 5e6,  "gpu_high": 1.5e7},
    "hash.sha512crypt":  {"cpu": 2e4,  "gpu_mid": 1e6,  "gpu_high": 5e6},
    "hash.bcrypt":       {"cpu": 5e2,  "gpu_mid": 3e4,  "gpu_high": 1e5},
    "hash.argon2":       {"cpu": 1e1,  "gpu_mid": 5e2,  "gpu_high": 2e3},
    "hash.scrypt":       {"cpu": 5e1,  "gpu_mid": 1e3,  "gpu_high": 5e3},
    "hash.mysql":        {"cpu": 1e9,  "gpu_mid": 1e10, "gpu_high": 4e10},
    "network.ntlmv2":    {"cpu": 1e7,  "gpu_mid": 3e9,  "gpu_high": 1e10},
    "network.ntlmv1":    {"cpu": 5e7,  "gpu_mid": 5e9,  "gpu_high": 2e10},
    "network.krb5tgs_rc4": {"cpu": 5e6, "gpu_mid": 1e9, "gpu_high": 3e9},
    "network.krb5asrep_rc4": {"cpu": 5e6, "gpu_mid": 1e9, "gpu_high": 3e9},
    "network.krb5tgs_aes128": {"cpu": 1e5, "gpu_mid": 1e7, "gpu_high": 5e7},
    "network.krb5tgs_aes256": {"cpu": 5e4, "gpu_mid": 5e6, "gpu_high": 2e7},
    "network.dcc1":      {"cpu": 1e8,  "gpu_mid": 5e9,  "gpu_high": 2e10},
    "network.dcc2":      {"cpu": 5e3,  "gpu_mid": 5e5,  "gpu_high": 2e6},
    "network.cisco_type5": {"cpu": 1e5, "gpu_mid": 2e7, "gpu_high": 7e7},
    "network.cisco_type8": {"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
    "network.cisco_type9": {"cpu": 5e1, "gpu_mid": 1e3, "gpu_high": 5e3},
    "token.ansible_vault": {"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
    "hash.jwt":          {"cpu": 1e7,  "gpu_mid": 5e8,  "gpu_high": 2e9},
}

# Common keyspace sizes
KEYSPACE = {
    "rockyou":    14_344_392,
    "top1000":    1_000,
    "top10000":   10_000,
    "4char_lower": 26**4,          # 456,976
    "6char_lower": 26**6,          # 308,915,776
    "8char_lower": 26**8,          # ~2e11
    "8char_alnum": 62**8,          # ~2e14
    "8char_full":  95**8,          # ~6.6e15
    "10char_full": 95**10,         # ~5.9e19
}


def _humanize_seconds(seconds: float) -> str:
    """Convert seconds to human-readable duration."""
    if seconds < 0.001:
        return "instant"
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"{seconds/86400:.1f} days"
    if seconds < 86400 * 365 * 100:
        return f"{seconds/(86400*365):.1f} years"
    return "centuries+"


def estimate_time(
    format_id: str,
    keyspace_size: int = KEYSPACE["rockyou"],
    hardware: str = "gpu_mid",
) -> TimeEstimate:
    """Estimate cracking time for a given format, keyspace, and hardware.

    Args:
        format_id: Hash format identifier
        keyspace_size: Total number of candidates to try
        hardware: One of 'cpu', 'gpu_mid', 'gpu_high'

    Returns:
        TimeEstimate with estimated cracking time
    """
    benchmarks = _BENCHMARKS.get(format_id, {})
    hps = benchmarks.get(hardware, 1e3)  # default fallback

    if hps <= 0:
        hps = 1

    seconds = keyspace_size / hps
    human = _humanize_seconds(seconds)
    feasible = seconds < 86400 * 30  # < 30 days

    return TimeEstimate(
        format_id=format_id,
        hardware=hardware,
        keyspace_size=keyspace_size,
        hashes_per_second=hps,
        estimated_seconds=seconds,
        estimated_human=human,
        feasible=feasible,
    )


def estimate_comparison(format_id: str, keyspace_size: int = KEYSPACE["rockyou"]) -> dict[str, TimeEstimate]:
    """Estimate cracking time across all hardware tiers."""
    return {
        tier: estimate_time(format_id, keyspace_size, tier)
        for tier in ("cpu", "gpu_mid", "gpu_high")
    }
