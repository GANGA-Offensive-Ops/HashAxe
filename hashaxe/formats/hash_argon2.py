# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/hash_argon2.py
#  Standalone Argon2 hash format handler for $argon2id$, $argon2i$, $argon2d$ variants.
#  Memory-hard KDF winner of PHC, used in modern password storage systems.
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
Standalone Argon2 hash format handler — $argon2id$, $argon2i$, $argon2d$.

Dependencies:
  - ``argon2-cffi`` (optional) for verification
"""
from __future__ import annotations

import base64
import logging
import re
from pathlib import Path
from typing import Optional

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

try:
    from argon2 import PasswordHasher, Type  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore

    _HAS_ARGON2 = True
    _PH = PasswordHasher()  # Cached instance — verify() is stateless
except ImportError:
    _HAS_ARGON2 = False
    _PH = None

# $argon2id$v=19$m=65536,t=3,p=4$salt$hash
_ARGON2_RE = re.compile(
    r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"
)


class Argon2Format(BaseFormat):
    """Handler for standalone Argon2 password hashes.

    Supports Argon2id (recommended), Argon2i, and Argon2d variants.
    """

    format_id = "hash.argon2"
    format_name = "Argon2 (id/i/d)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        if _ARGON2_RE.match(text):
            variant = (
                "argon2id"
                if "$argon2id$" in text
                else ("argon2i" if "$argon2i$" in text else "argon2d")
            )
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": f"Argon2 hash ({variant})"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        # Parse parameters
        parts = text.split("$")
        variant = parts[1]  # argon2id, argon2i, argon2d
        params_str = parts[3]  # m=65536,t=3,p=4
        params = {}
        for p in params_str.split(","):
            k, v = p.split("=")
            params[k] = int(v)

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"{variant} (m={params.get('m', 0)}, t={params.get('t', 0)}, p={params.get('p', 0)})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.EXTREME,
            format_data={
                "target_hash": text,
                "full_hash": text,
                "variant": variant,
                "memory_cost": params.get("m", 65536),
                "time_cost": params.get("t", 3),
                "parallelism": params.get("p", 4),
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        if not _HAS_ARGON2:
            log.warning("argon2-cffi not installed — Argon2 cracking unavailable")
            return False

        full_hash = target.format_data["full_hash"]
        try:
            return _PH.verify(full_hash, password.decode("utf-8", errors="replace"))
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.EXTREME

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        return {
            "Algorithm": target.format_data.get("variant", "argon2id"),
            "Memory": f"{target.format_data.get('memory_cost', 0):,} KiB",
            "Iterations": str(target.format_data.get("time_cost", 0)),
            "Parallelism": str(target.format_data.get("parallelism", 0)),
            "argon2-cffi": "Yes" if _HAS_ARGON2 else "No (install argon2-cffi)",
            "Difficulty": "EXTREME (single-digit pw/s)",
        }


_registry = FormatRegistry()
_registry.register(Argon2Format())
