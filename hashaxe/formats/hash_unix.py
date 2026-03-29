# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/hash_unix.py
#  Unix crypt hash format handler for md5crypt ($1$), sha256crypt ($5$), sha512crypt ($6$).
#  Standard /etc/shadow hash formats found on every Linux/BSD system.
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
Unix crypt hash format handler — md5crypt ($1$), sha256crypt ($5$), sha512crypt ($6$).

These are the standard /etc/shadow hash formats found on every Linux/BSD system.
Uses Python's `crypt` module (POSIX) or `passlib` as fallback.
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Optional

from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# ── Try to import crypt backends ──────────────────────────────────────────────

_HAS_CRYPT = False
_HAS_PASSLIB = False

try:
    import crypt as _crypt_mod

    _HAS_CRYPT = True
except ImportError:
    pass

try:
    from passlib.hash import des_crypt, md5_crypt, sha256_crypt, sha512_crypt

    _HAS_PASSLIB = True
except ImportError:
    pass


# ── Regex patterns ────────────────────────────────────────────────────────────

_MD5CRYPT_RE = re.compile(r"^\$1\$([./A-Za-z0-9]{1,8})\$([./A-Za-z0-9]{22})$")
_SHA256CRYPT_RE = re.compile(r"^\$5\$(rounds=(\d+)\$)?([./A-Za-z0-9]+)\$([./A-Za-z0-9]{43})$")
_SHA512CRYPT_RE = re.compile(r"^\$6\$(rounds=(\d+)\$)?([./A-Za-z0-9]+)\$([./A-Za-z0-9]{86})$")


def _verify_crypt(password: str, full_hash: str) -> bool:
    """Verify using the best available crypt backend."""
    if _HAS_PASSLIB:
        if full_hash.startswith("$1$"):
            return md5_crypt.verify(password, full_hash)
        elif full_hash.startswith("$5$"):
            return sha256_crypt.verify(password, full_hash)
        elif full_hash.startswith("$6$"):
            return sha512_crypt.verify(password, full_hash)
        elif len(full_hash) == 13 and not full_hash.startswith("$"):
            try:
                return des_crypt.verify(password, full_hash)
            except ValueError:
                return False

    if _HAS_CRYPT:
        return _crypt_mod.crypt(password, full_hash) == full_hash

    log.error("No crypt backend available. Install passlib: pip install passlib")
    return False


class UnixCryptFormat(BaseFormat):
    """Handler for Unix crypt hashes: md5crypt, sha256crypt, sha512crypt.

    Difficulty ranges from MEDIUM (md5crypt, ~100K pw/s) to HARD
    (sha512crypt with rounds=500000, ~10 pw/s).
    """

    format_id = "hash.unix_crypt"
    format_name = "Unix Crypt (md5crypt / sha256crypt / sha512crypt)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        # Strip comment lines (e.g. "# DES crypt legacy hash")
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not lines:
            return None
        text = lines[0].strip()

        # Extract hash from shadow line if needed
        if ":" in text:
            parts = text.split(":")
            if len(parts) >= 2 and parts[1].startswith("$"):
                text = parts[1]

        if _SHA512CRYPT_RE.match(text):
            return FormatMatch(
                format_id="hash.sha512crypt",
                handler=self,
                confidence=1.0,
                metadata={"description": "sha512crypt $6$"},
            )
        if _SHA256CRYPT_RE.match(text):
            return FormatMatch(
                format_id="hash.sha256crypt",
                handler=self,
                confidence=1.0,
                metadata={"description": "sha256crypt $5$"},
            )
        if _MD5CRYPT_RE.match(text):
            return FormatMatch(
                format_id="hash.md5crypt",
                handler=self,
                confidence=1.0,
                metadata={"description": "md5crypt $1$"},
            )
        if len(text) == 13 and not text.startswith("$") and re.match(r"^[./A-Za-z0-9]{13}$", text):
            return FormatMatch(
                format_id="hash.descrypt",
                handler=self,
                confidence=0.8,
                metadata={"description": "descrypt"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip()

        # Strip comment lines (e.g. "# DES crypt legacy hash")
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not lines:
            raise ValueError("Empty hash file (only comments)")
        text = lines[0].strip()

        # Extract from shadow line
        if ":" in text:
            parts = text.split(":")
            if len(parts) >= 2 and parts[1].startswith("$"):
                text = parts[1]

        # Determine variant and extract metadata
        if text.startswith("$6$"):
            variant = "sha512crypt"
            fmt_id = "hash.sha512crypt"
            m = _SHA512CRYPT_RE.match(text)
            rounds = int(m.group(2)) if m and m.group(2) else 5000
            salt = m.group(3) if m else ""
        elif text.startswith("$5$"):
            variant = "sha256crypt"
            fmt_id = "hash.sha256crypt"
            m = _SHA256CRYPT_RE.match(text)
            rounds = int(m.group(2)) if m and m.group(2) else 5000
            salt = m.group(3) if m else ""
        elif text.startswith("$1$"):
            variant = "md5crypt"
            fmt_id = "hash.md5crypt"
            m = _MD5CRYPT_RE.match(text)
            rounds = 1000  # md5crypt is fixed
            salt = m.group(1) if m else ""
        elif len(text) == 13 and not text.startswith("$"):
            # Classic descrypt
            variant = "descrypt"
            fmt_id = "hash.descrypt"
            rounds = 1
            salt = text[:2]
        else:
            raise ValueError(f"Unrecognised Unix crypt format: {text[:20]}...")

        difficulty = (
            FormatDifficulty.SLOW
            if rounds >= 100_000
            else (FormatDifficulty.MEDIUM if rounds >= 5000 else FormatDifficulty.FAST)
        )

        return FormatTarget(
            format_id=fmt_id,
            display_name=f"{variant} hash",
            source_path=str(path) if path else None,
            is_encrypted=True,
            difficulty=difficulty,
            format_data={
                "variant": variant,
                "full_hash": text,
                "target_hash": text,
                "salt": salt,
                "rounds": rounds,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        pw_str = password.decode("utf-8", errors="replace")
        full_hash = target.format_data["full_hash"]
        return _verify_crypt(pw_str, full_hash)

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict:
        return {
            "Variant": target.format_data.get("variant", "unknown"),
            "Salt": target.format_data.get("salt", ""),
            "Rounds": str(target.format_data.get("rounds", "")),
            "Hash": target.format_data.get("full_hash", "")[:30] + "...",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
from hashaxe.formats._registry import FormatRegistry

_registry = FormatRegistry()
_unix_handler = UnixCryptFormat()
_registry.register(_unix_handler)
# Also register under specific variant IDs returned by can_handle()/parse()
for _variant_id in ("hash.md5crypt", "hash.sha256crypt", "hash.sha512crypt", "hash.descrypt"):
    _registry._handlers[_variant_id] = _unix_handler
