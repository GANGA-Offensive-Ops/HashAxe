# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/classifier.py
#  Smart Hash Classifier combining regex, entropy, and context analysis.
#  Produces confidence-weighted identification for ambiguous hash formats.
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
hashaxe.identify.classifier — Smart Hash Classifier.

Combines regex pattern matching with structural analysis, entropy scoring,
and context clues to produce the most accurate hash type identification.
This is the upgraded replacement for basic pattern matching when dealing
with ambiguous formats (e.g., raw 32-hex could be MD5, NTLM, or DCC1).

Strategy:
  1. Pattern match (regex) → initial candidates
  2. Entropy analysis → rule out low-entropy false positives
  3. Context clues → username:hash, shadow format, config file context
  4. Multi-match ranking → confidence-weighted final result
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Optional

from hashaxe.identify.hash_patterns import HashMatch, identify_hash, identify_best

log = logging.getLogger(__name__)


@dataclass
class ClassifiedHash:
    """Rich classification result with attack recommendations."""
    format_id: str
    algorithm: str
    confidence: float
    hashcat_mode: int | None = None
    john_format: str | None = None
    difficulty: str = "unknown"
    estimated_speed: str = "unknown"
    attack_recommendation: str = ""
    all_candidates: list[HashMatch] = field(default_factory=list)
    context: dict = field(default_factory=dict)


# ── Hashcat mode mapping ─────────────────────────────────────────────────────
_HASHCAT_MODES: dict[str, int] = {
    "hash.md5": 0,
    "hash.sha1": 100,
    "hash.sha256": 1400,
    "hash.sha384": 10800,
    "hash.sha512": 1700,
    "hash.sha224": 1300,
    "hash.md5crypt": 500,
    "hash.sha256crypt": 7400,
    "hash.sha512crypt": 1800,
    "hash.bcrypt": 3200,
    "hash.argon2": 32500,
    "hash.scrypt": 8900,
    "hash.descrypt": 1500,
    "hash.mysql": 300,
    "hash.postgres": 12,
    "hash.mssql2005": 132,
    "hash.mssql2012": 1731,
    "hash.jwt": 16500,
    "network.ntlmv1": 5500,
    "network.ntlmv2": 5600,
    "network.krb5tgs_rc4": 13100,
    "network.krb5asrep_rc4": 18200,
    "network.krb5tgs_aes128": 19600,
    "network.krb5tgs_aes256": 19700,
    "network.dcc1": 1100,
    "network.dcc2": 2100,
    "disk.dpapi": 15300,
    "token.ansible_vault": 16900,
    "network.cisco_type5": 500,
    "network.cisco_type8": 9200,
    "network.cisco_type9": 9300,
}

_JOHN_FORMATS: dict[str, str] = {
    "hash.md5": "Raw-MD5",
    "hash.sha1": "Raw-SHA1",
    "hash.sha256": "Raw-SHA256",
    "hash.sha512": "Raw-SHA512",
    "hash.md5crypt": "md5crypt",
    "hash.sha256crypt": "sha256crypt",
    "hash.sha512crypt": "sha512crypt",
    "hash.bcrypt": "bcrypt",
    "hash.mysql": "mysql-sha1",
    "network.ntlmv2": "netntlmv2",
    "network.krb5tgs_rc4": "krb5tgs",
    "network.krb5asrep_rc4": "krb5asrep",
    "network.dcc2": "DCC2",
    "network.dcc1": "DCC",
}

_DIFFICULTY_MAP: dict[str, str] = {
    "hash.md5": "TRIVIAL",
    "hash.sha1": "TRIVIAL",
    "hash.sha256": "TRIVIAL",
    "hash.sha512": "FAST",
    "hash.md5crypt": "FAST",
    "hash.sha256crypt": "MEDIUM",
    "hash.sha512crypt": "MEDIUM",
    "hash.bcrypt": "SLOW",
    "hash.argon2": "EXTREME",
    "hash.scrypt": "EXTREME",
    "hash.mysql": "TRIVIAL",
    "network.ntlmv2": "FAST",
    "network.krb5tgs_rc4": "FAST",
    "network.krb5asrep_rc4": "FAST",
    "network.dcc1": "FAST",
    "network.dcc2": "SLOW",
    "token.ansible_vault": "SLOW",
    "network.cisco_type8": "SLOW",
    "network.cisco_type9": "EXTREME",
}

_SPEED_MAP: dict[str, str] = {
    "TRIVIAL": "~10 GH/s (GPU)",
    "FAST":    "~1 GH/s (GPU)",
    "MEDIUM":  "~100 MH/s (GPU)",
    "SLOW":    "~10 KH/s (GPU)",
    "EXTREME": "~100 H/s (GPU)",
}


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _detect_context(text: str) -> dict:
    """Detect contextual information about the hash source."""
    ctx: dict = {}

    # Shadow file format
    if re.match(r'^[a-zA-Z0-9._-]+:\$\d\$', text):
        ctx["source"] = "shadow_file"
        ctx["username"] = text.split(":")[0]

    # Windows hashdump
    elif re.match(r'^[A-Za-z0-9._-]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}', text):
        ctx["source"] = "windows_hashdump"
        ctx["username"] = text.split(":")[0]

    # Cisco running-config
    elif re.match(r'^enable\s+(secret|password)\s+', text, re.IGNORECASE):
        ctx["source"] = "cisco_config"

    # Hash:username (DCC style)
    elif re.match(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9._@-]+$', text):
        ctx["source"] = "dcc_format"
        ctx["username"] = text.split(":")[-1]

    return ctx


def classify(text: str) -> ClassifiedHash:
    """Classify a hash string with full intelligence.

    This is the main entry point for the smart classifier.
    Returns a ClassifiedHash with format, difficulty, and attack guidance.
    """
    text = text.strip()
    if not text:
        return ClassifiedHash(
            format_id="unknown",
            algorithm="Unknown",
            confidence=0.0,
        )

    matches = identify_hash(text)
    ctx = _detect_context(text)

    if not matches:
        # Entropy-based fallback for unrecognized formats
        ent = _entropy(text)
        return ClassifiedHash(
            format_id="unknown",
            algorithm="Unknown",
            confidence=0.0,
            context={"entropy": ent, **ctx},
            attack_recommendation="Hash format not recognized. Try: hashcat --identify or john --list=formats",
        )

    best = matches[0]

    difficulty = _DIFFICULTY_MAP.get(best.format_id, "unknown")
    speed = _SPEED_MAP.get(difficulty, "unknown")
    hashcat = _HASHCAT_MODES.get(best.format_id)
    john = _JOHN_FORMATS.get(best.format_id)

    # Build attack recommendation
    recommendation = _build_recommendation(best, difficulty, hashcat)

    return ClassifiedHash(
        format_id=best.format_id,
        algorithm=best.algorithm,
        confidence=best.confidence,
        hashcat_mode=hashcat,
        john_format=john,
        difficulty=difficulty,
        estimated_speed=speed,
        attack_recommendation=recommendation,
        all_candidates=matches,
        context=ctx,
    )


def _build_recommendation(match: HashMatch, difficulty: str, hashcat_mode: int | None) -> str:
    """Generate attack-specific recommendations."""
    lines: list[str] = []

    if hashcat_mode is not None:
        lines.append(f"hashcat -m {hashcat_mode} hash.txt wordlist.txt")

    if difficulty in ("TRIVIAL", "FAST"):
        lines.append("Recommended: Wordlist + rules attack (rockyou + best64)")
        lines.append("Fallback: Mask attack ?a?a?a?a?a?a?a?a")
    elif difficulty == "MEDIUM":
        lines.append("Recommended: Targeted wordlist + simple rules")
        lines.append("Avoid: Brute-force (too slow)")
    elif difficulty in ("SLOW", "EXTREME"):
        lines.append("Recommended: Small targeted wordlist only")
        lines.append("Warning: Very slow — GPU required for any real attempt")

    return "\n".join(lines)


def classify_batch(hashes: list[str]) -> list[ClassifiedHash]:
    """Classify multiple hashes at once."""
    return [classify(h) for h in hashes]
