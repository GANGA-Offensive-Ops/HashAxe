# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/__init__.py
#  Auto-identification engine for detecting hash formats and file types.
#  Uses magic bytes, hash patterns, and entropy analysis for format detection.
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
Hashaxe V3 — Auto-Identification Engine

Feed any file, hash string, or raw bytes → the engine identifies the format
and returns the best-matching format handler from the FormatRegistry.

Detection pipeline:
  1. Magic bytes   → binary file format (SSH key, ZIP, PDF, 7z, PCAP)
  2. Hash patterns → structured hash string (bcrypt, argon2, unix crypt, JWT)
  3. Entropy       → raw hex digest fallback (MD5, SHA-1, SHA-256, SHA-512)

GANGA Offensive Ops · Hashaxe V3
"""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple, Optional

from hashaxe.identify.entropy import EntropyResult, analyze, suggest_hash_type
from hashaxe.identify.hash_patterns import HashMatch, identify_best, identify_hash
from hashaxe.identify.magic import MagicMatch, identify_best_magic, identify_magic


class IdentifyResult(NamedTuple):
    """Unified identification result."""
    format_id: str          # Best-guess format ID (e.g. "hash.md5", "ssh.openssh")
    algorithm: str          # Human-readable name
    confidence: float       # 0.0–1.0
    source: str             # "magic" | "pattern" | "entropy"
    details: dict           # Format-specific metadata


class MagicIdentifier:
    """Unified identification engine.

    Given arbitrary input (file path, raw bytes, hash string), applies
    magic → pattern → entropy pipeline and returns the best identification.
    """

    def identify(self, inp: str | bytes | Path) -> IdentifyResult | None:
        """Auto-identify the format of any input.

        Args:
            inp: A file path (str/Path), raw bytes, or a hash string.

        Returns:
            IdentifyResult with the best identification, or None.
        """
        # ── Stage 0: Determine input type ─────────────────────────────────────
        raw_bytes: bytes | None = None
        text: str | None = None
        file_path: Path | None = None

        if isinstance(inp, (str, Path)):
            p = Path(inp)
            if p.exists() and p.is_file():
                file_path = p
                try:
                    raw_bytes = p.read_bytes()
                except OSError:
                    pass
            else:
                # Treat as a hash string
                text = str(inp)
        elif isinstance(inp, bytes):
            raw_bytes = inp
        else:
            return None

        # ── Stage 1: Magic byte detection (binary files) ──────────────────────
        if raw_bytes is not None:
            magic = identify_best_magic(raw_bytes)
            if magic and magic.confidence >= 0.7:
                return IdentifyResult(
                    format_id=magic.format_id,
                    algorithm=magic.description,
                    confidence=magic.confidence,
                    source="magic",
                    details={"path": str(file_path) if file_path else None},
                )

            # If raw_bytes looks like text, decode for pattern matching
            try:
                text = raw_bytes.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError:
                pass

        # ── Stage 2: Hash pattern matching (structured strings) ───────────────
        if text:
            match = identify_best(text)
            if match and match.confidence >= 0.5:
                return IdentifyResult(
                    format_id=match.format_id,
                    algorithm=match.algorithm,
                    confidence=match.confidence,
                    source="pattern",
                    details=match.details,
                )

        # ── Stage 3: Entropy-based fallback (raw hex digests) ─────────────────
        if text:
            result = analyze(text)
            if result.is_likely_hash and result.confidence >= 0.5:
                # Use length-based suggestion
                suggestions = suggest_hash_type(text)
                algo = suggestions[0] if suggestions else f"Unknown ({len(text)}-char hex)"
                fmt_id = f"hash.{algo.lower().replace('-', '').replace(' ', '_')}"

                return IdentifyResult(
                    format_id=fmt_id,
                    algorithm=algo,
                    confidence=result.confidence,
                    source="entropy",
                    details={
                        "entropy": result.entropy,
                        "charset": result.charset,
                        "candidates": suggestions,
                    },
                )

        return None

    def identify_all(self, inp: str | bytes | Path) -> list[IdentifyResult]:
        """Return ALL possible identifications, not just the best.

        Useful for ambiguous inputs (e.g., 32-hex could be MD5 or NTLM).
        """
        results: list[IdentifyResult] = []
        text: str | None = None
        raw_bytes: bytes | None = None

        if isinstance(inp, (str, Path)):
            p = Path(inp)
            if p.exists() and p.is_file():
                try:
                    raw_bytes = p.read_bytes()
                except OSError:
                    pass
            else:
                text = str(inp)
        elif isinstance(inp, bytes):
            raw_bytes = inp

        # Magic
        if raw_bytes:
            for m in identify_magic(raw_bytes):
                results.append(IdentifyResult(
                    format_id=m.format_id,
                    algorithm=m.description,
                    confidence=m.confidence,
                    source="magic",
                    details={},
                ))
            try:
                text = raw_bytes.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError:
                pass

        # Patterns
        if text:
            for h in identify_hash(text):
                results.append(IdentifyResult(
                    format_id=h.format_id,
                    algorithm=h.algorithm,
                    confidence=h.confidence,
                    source="pattern",
                    details=h.details,
                ))

        # Sort by confidence
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results


# Convenience singleton
_identifier = MagicIdentifier()
auto_identify    = _identifier.identify
auto_identify_all = _identifier.identify_all

__all__ = [
    "EntropyResult",
    "HashMatch",
    "IdentifyResult",
    "MagicIdentifier",
    "MagicMatch",
    "auto_identify",
    "auto_identify_all",
]
