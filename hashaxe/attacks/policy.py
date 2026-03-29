# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/policy.py
#  Policy-constrained attack mode — generate candidates matching password policies.
#  Filters candidates against constraints like length, uppercase, digits, symbols.
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
Policy-constrained attack mode — generate candidates matching password policies.

Parse a policy string like: "len>=8,upper,digit,symbol,len<=16"

Constraints:
  len>=N     — minimum length
  len<=N     — maximum length
  upper      — must contain uppercase
  lower      — must contain lowercase
  digit      — must contain digit
  symbol     — must contain symbol
  no_repeat  — no consecutive repeated characters

Candidates are generated from a charset in probability order,
filtered against the policy constraints.
"""
from __future__ import annotations

import logging
import re
import string
from collections.abc import Iterator
from itertools import product
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)


def _parse_policy(policy_str: str) -> dict:
    """Parse policy string into constraint dictionary."""
    constraints = {
        "min_length": 1,
        "max_length": 64,
        "require_upper": False,
        "require_lower": False,
        "require_digit": False,
        "require_symbol": False,
        "no_repeat": False,
    }

    for part in policy_str.split(","):
        part = part.strip().lower()
        if not part:
            continue

        if part.startswith("len>="):
            constraints["min_length"] = int(part[5:])
        elif part.startswith("len<="):
            constraints["max_length"] = int(part[5:])
        elif part == "upper":
            constraints["require_upper"] = True
        elif part == "lower":
            constraints["require_lower"] = True
        elif part == "digit":
            constraints["require_digit"] = True
        elif part == "symbol":
            constraints["require_symbol"] = True
        elif part == "no_repeat":
            constraints["no_repeat"] = True

    return constraints


def _check_policy(candidate: str, constraints: dict) -> bool:
    """Check if a candidate matches all policy constraints."""
    length = len(candidate)

    if length < constraints["min_length"] or length > constraints["max_length"]:
        return False
    if constraints["require_upper"] and not any(c.isupper() for c in candidate):
        return False
    if constraints["require_lower"] and not any(c.islower() for c in candidate):
        return False
    if constraints["require_digit"] and not any(c.isdigit() for c in candidate):
        return False
    if constraints["require_symbol"] and not any(c in string.punctuation for c in candidate):
        return False
    if constraints["no_repeat"]:
        for i in range(1, length):
            if candidate[i] == candidate[i - 1]:
                return False
    return True


class PolicyAttack(BaseAttack):
    """Generate candidates constrained by password policy rules."""

    attack_id = "policy"
    attack_name = "Policy-Constrained Attack"
    description = "Generate candidates matching password policy (len>=8,upper,digit,symbol)."

    def generate(self, config: AttackConfig) -> Iterator[str]:
        if not config.policy:
            return

        constraints = _parse_policy(config.policy)

        # If a wordlist is provided, filter it against the policy
        if config.wordlist:
            yield from self._filter_wordlist(config.wordlist, constraints)
        else:
            # Generate from charset (brute-force within policy)
            yield from self._generate_brute(constraints, config)

    def _filter_wordlist(self, wordlist_path: str, constraints: dict) -> Iterator[str]:
        """Filter a wordlist against policy constraints."""
        try:
            with open(wordlist_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    candidate = line.rstrip("\n\r")
                    if candidate and _check_policy(candidate, constraints):
                        yield candidate
        except OSError as e:
            log.error("Cannot read wordlist: %s", e)

    def _generate_brute(self, constraints: dict, config: AttackConfig) -> Iterator[str]:
        """Brute-force generation within policy constraints."""
        # Build charset based on required classes
        charset = ""
        if constraints["require_lower"] or not any(
            [
                constraints["require_upper"],
                constraints["require_digit"],
                constraints["require_symbol"],
            ]
        ):
            charset += string.ascii_lowercase
        if constraints["require_upper"]:
            charset += string.ascii_uppercase
        if constraints["require_digit"]:
            charset += string.digits
        if constraints["require_symbol"]:
            charset += "!@#$%^&*()-_=+"

        if not charset:
            charset = string.ascii_lowercase + string.digits

        min_len = constraints["min_length"]
        max_len = min(constraints["max_length"], config.max_length)

        for length in range(min_len, max_len + 1):
            for combo in product(charset, repeat=length):
                candidate = "".join(combo)
                if _check_policy(candidate, constraints):
                    yield candidate

    def estimate_keyspace(self, config: AttackConfig) -> int:
        if not config.policy:
            return 0
        if config.wordlist:
            try:
                return sum(1 for line in open(config.wordlist, errors="replace") if line.strip())
            except OSError:
                return 0

        constraints = _parse_policy(config.policy)
        charset_size = 0
        if constraints["require_lower"]:
            charset_size += 26
        if constraints["require_upper"]:
            charset_size += 26
        if constraints["require_digit"]:
            charset_size += 10
        if constraints["require_symbol"]:
            charset_size += 14
        if charset_size == 0:
            charset_size = 36

        total = 0
        min_len = constraints["min_length"]
        max_len = min(constraints["max_length"], config.max_length)
        for l in range(min_len, max_len + 1):
            total += charset_size**l
        return total

    def validate_config(self, config: AttackConfig) -> str | None:
        if not config.policy:
            return "Policy attack requires --policy"
        return None


_registry = AttackRegistry()
_registry.register(PolicyAttack())
