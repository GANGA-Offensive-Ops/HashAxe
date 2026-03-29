# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/hash_raw.py
#  Raw hash format handler for MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, NTLM.
#  Fastest hash types with single hashlib call per candidate, 5M-50M pw/s per core.
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
Raw hash format handler — MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, NTLM.

These are the fastest possible hash types: a single hashlib call per candidate.
GPU-friendly in the extreme.  On a modern CPU, expect 5M–50M pw/s per core
for raw hashes.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)


# ── Supported algorithms ──────────────────────────────────────────────────────
# Maps format_id → (hashlib_name, hex_digest_length)
_ALGOS: dict[str, tuple[str, int]] = {
    "hash.md5":    ("md5",    32),
    "hash.sha1":   ("sha1",   40),
    "hash.sha224": ("sha224", 56),
    "hash.sha256": ("sha256", 64),
    "hash.sha384": ("sha384", 96),
    "hash.sha512": ("sha512", 128),
}


class RawHashFormat(BaseFormat):
    """Handler for raw unsalted hash digests.

    Supported: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.

    Verification is trivially fast:
        hashlib.new(algo, candidate).hexdigest() == target_hash
    """

    format_id   = "hash.raw"
    format_name = "Raw Hash (MD5/SHA-1/SHA-256/SHA-512)"

    # ── Identification ────────────────────────────────────────────────────────

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Check if data is a raw hex digest of a known length."""
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None

        # Must be pure hex
        try:
            bytes.fromhex(text)
        except ValueError:
            return None

        length = len(text)
        for fmt_id, (algo_name, expected_len) in _ALGOS.items():
            if length == expected_len:
                return FormatMatch(
                    format_id=fmt_id,
                    handler=self,
                    confidence=0.7,
                    metadata={"description": f"{algo_name.upper()} ({expected_len}-char hex digest)"},
                )
        return None

    # ── Parsing ───────────────────────────────────────────────────────────────

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        """Parse a raw hex hash string into a FormatTarget."""
        text = data.decode("utf-8", errors="strict").strip().lower()
        length = len(text)

        # Determine the algorithm
        algo_name = "unknown"
        fmt_id = "hash.raw"
        for fid, (aname, expected_len) in _ALGOS.items():
            if length == expected_len:
                algo_name = aname
                fmt_id = fid
                break

        return FormatTarget(
            format_id=fmt_id,
            display_name=f"{algo_name.upper()} hash",
            source_path=str(path) if path else None,
            is_encrypted=True,  # "encrypted" = needs cracking
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={
                "algorithm": algo_name,
                "target_hash": text,
                "target_hash_bytes": bytes.fromhex(text),  # pre-convert for fast digest() comparison
                "hex_length": length,
            },
        )

    # ── Verification (HOT PATH) ──────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Fast-path: single hashlib comparison.

        This is the innermost loop — called millions of times per second.
        Every nanosecond matters here.
        Uses digest() (raw bytes, 16-32 bytes) instead of hexdigest()
        (string, 32-128 chars) for ~2x faster comparison.

        For 32-hex hashes identified as MD5, also tries NTLM (MD4 UTF-16LE)
        since NTLM and MD5 are structurally identical (both 32 hex chars).
        """
        algo = target.format_data["algorithm"]
        expected = target.format_data["target_hash_bytes"]
        if hashlib.new(algo, password, usedforsecurity=False).digest() == expected:
            return True
        # NTLM fallback for 32-hex hashes that might be NTLM instead of MD5
        if algo == "md5":
            try:
                pw_str = password.decode("utf-8", "replace")
                ntlm_digest = hashlib.new(
                    "md4", pw_str.encode("utf-16-le"), usedforsecurity=False
                ).digest()
                if ntlm_digest == expected:
                    return True
            except ValueError:
                pass  # MD4 not available
        return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """Full verification — identical to fast path for raw hashes."""
        return self.verify(target, password)

    # ── Metadata ──────────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict:
        return {
            "Algorithm": target.format_data.get("algorithm", "unknown").upper(),
            "Hash": target.format_data.get("target_hash", "")[:16] + "...",
            "Difficulty": "TRIVIAL (millions pw/s)",
        }


class NTLMFormat(BaseFormat):
    """Handler for NTLM hashes.

    NTLM = MD4(UTF-16LE(password))
    32-character hex digest, extremely fast to compute.
    """

    format_id   = "hash.ntlm"
    format_name = "NTLM"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Low-confidence detection for NTLM (32-hex chars).

        NTLM hashes are indistinguishable from MD5 by format alone.
        We return a low confidence (0.3) so NTLM appears in multi-candidate
        results but does not override MD5 (which returns 0.7).
        Use --format hash.ntlm for explicit selection.
        """
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None
        if len(text) != 32:
            return None
        try:
            bytes.fromhex(text)
        except ValueError:
            return None
        return FormatMatch(
            format_id="hash.ntlm",
            handler=self,
            confidence=0.3,
            metadata={"description": "NTLM (32-char hex, ambiguous with MD5)"},
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip().lower()
        return FormatTarget(
            format_id="hash.ntlm",
            display_name="NTLM hash",
            source_path=str(path) if path else None,
            is_encrypted=True,
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={
                "algorithm": "ntlm",
                "target_hash": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """NTLM = MD4(UTF-16LE(password))"""
        try:
            md4 = hashlib.new("md4", password.decode("utf-8", "replace").encode("utf-16-le"))
            return md4.hexdigest() == target.format_data["target_hash"]
        except ValueError:
            # MD4 not available in all OpenSSL builds
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict:
        return {
            "Algorithm": "NTLM (MD4 UTF-16LE)",
            "Hash": target.format_data.get("target_hash", "")[:16] + "...",
            "Difficulty": "TRIVIAL (millions pw/s)",
        }

class LMFormat(BaseFormat):
    """Handler for LM hashes.

    16-byte hex digest, extremely fast.
    """

    format_id   = "hash.lm"
    format_name = "LM"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Low-confidence detection for LM (32-hex chars).

        LM hashes share length with MD5/NTLM.
        Confidence 0.25 — lowest priority among 32-hex candidates.
        Use --format hash.lm for explicit selection.
        """
        try:
            text = data.decode("utf-8", errors="strict").strip()
        except (UnicodeDecodeError, AttributeError):
            return None
        if len(text) != 32:
            return None
        try:
            bytes.fromhex(text)
        except ValueError:
            return None
        return FormatMatch(
            format_id="hash.lm",
            handler=self,
            confidence=0.25,
            metadata={"description": "LM hash (32-char hex, ambiguous with MD5/NTLM)"},
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        text = data.decode("utf-8", errors="strict").strip().lower()
        return FormatTarget(
            format_id="hash.lm",
            display_name="LM hash",
            source_path=str(path) if path else None,
            is_encrypted=True,
            difficulty=FormatDifficulty.TRIVIAL,
            format_data={
                "algorithm": "lm",
                "target_hash": text,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        # Python verification is unsupported for LM. Returns False to prevent false-positives.
        # Hashcat mode 3000 natively handles actual evaluation when delegated.
        return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return False

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.TRIVIAL

    def display_info(self, target: FormatTarget) -> dict:
        return {
            "Algorithm": "LM",
            "Hash": target.format_data.get("target_hash", "")[:16] + "...",
            "Difficulty": "TRIVIAL (millions pw/s)",
        }

# ── Auto-register ────────────────────────────────────────────────────────────
from hashaxe.formats._registry import FormatRegistry
_registry = FormatRegistry()
_raw_handler = RawHashFormat()
_registry.register(_raw_handler)
# Also register under each specific algo ID so workers can look up by
# the FormatTarget.format_id (e.g. "hash.md5", "hash.sha256")
for _algo_id in _ALGOS:
    _registry._handlers[_algo_id] = _raw_handler
_registry.register(NTLMFormat())
_registry.register(LMFormat())
