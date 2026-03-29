# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/magic.py
#  File magic byte detection for binary format identification.
#  Identifies SSH keys, archives, PDFs, and other encrypted file formats.
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
File magic byte detection for binary format identification.

Checks the first N bytes of a file or buffer to identify format:
SSH keys (OpenSSH, PEM, PPK), ZIP archives, PDF documents,
7-Zip archives, and more.
"""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple


class MagicMatch(NamedTuple):
    """Result of magic byte analysis."""
    format_id: str       # e.g. "ssh.openssh", "archive.zip"
    description: str     # Human-readable, e.g. "OpenSSH private key"
    confidence: float    # 0.0–1.0


# ──────────────────────────────────────────────────────────────────────────────
# Magic signature database
# Each entry: (magic_bytes, offset, format_id, description, confidence)
#
# Entries are checked in order.  First *confident* match wins.
# ──────────────────────────────────────────────────────────────────────────────

_SIGNATURES: list[tuple[bytes, int, str, str, float]] = [
    # ── SSH keys ──────────────────────────────────────────────────────────────
    (b"openssh-key-v1\x00",   0, "ssh.openssh", "OpenSSH private key (new format)", 1.0),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", 0, "ssh.openssh", "OpenSSH private key (PEM)", 1.0),
    (b"-----BEGIN RSA PRIVATE KEY-----",     0, "ssh.openssh", "RSA private key (PEM)", 1.0),
    (b"-----BEGIN EC PRIVATE KEY-----",      0, "ssh.openssh", "ECDSA private key (PEM)", 1.0),
    (b"-----BEGIN DSA PRIVATE KEY-----",     0, "ssh.openssh", "DSA private key (PEM)", 1.0),
    (b"-----BEGIN ENCRYPTED PRIVATE KEY-----", 0, "ssh.openssh", "Encrypted PKCS#8 key", 0.9),
    (b"-----BEGIN PRIVATE KEY-----",         0, "ssh.openssh", "PKCS#8 private key", 0.85),
    (b"PuTTY-User-Key-File-3:",              0, "ssh.ppk", "PuTTY PPK v3 key", 1.0),
    (b"PuTTY-User-Key-File-2:",              0, "ssh.ppk", "PuTTY PPK v2 key", 1.0),

    # ── Archives ──────────────────────────────────────────────────────────────
    (b"PK\x03\x04",                          0, "archive.zip", "ZIP archive", 0.95),
    (b"PK\x05\x06",                          0, "archive.zip", "ZIP archive (empty)", 0.9),
    (b"7z\xbc\xaf\x27\x1c",                  0, "archive.7z", "7-Zip archive", 0.95),
    (b"Rar!\x1a\x07",                        0, "archive.rar", "RAR archive", 0.95),

    # ── Documents ─────────────────────────────────────────────────────────────
    (b"%PDF-",                               0, "document.pdf", "PDF document", 0.95),

    # ── Databases ─────────────────────────────────────────────────────────────
    (b"SQLite format 3\x00",                 0, "database.sqlite", "SQLite database", 0.95),

    # ── Crypto wallets ────────────────────────────────────────────────────────
    (b"\x00\x00\x00\x00\x01\x00\x00\x00",   0, "crypto.wallet", "Bitcoin wallet.dat", 0.5),

    # ── Network captures ──────────────────────────────────────────────────────
    (b"\xd4\xc3\xb2\xa1",                    0, "network.pcap", "PCAP (little-endian)", 0.95),
    (b"\xa1\xb2\xc3\xd4",                    0, "network.pcap", "PCAP (big-endian)", 0.95),
    (b"\x0a\x0d\x0d\x0a",                    0, "network.pcapng", "PCAPNG", 0.9),

    # ── WPA handshake ─────────────────────────────────────────────────────────
    (b"HCCAPX\x00\x00\x00\x04",             0, "network.hccapx", "hccapx WPA handshake", 0.95),
]


def identify_magic(data: bytes) -> list[MagicMatch]:
    """Check raw bytes against the magic signature database.

    Args:
        data: Raw file bytes (at least first 256 bytes recommended).

    Returns:
        List of MagicMatch results, ordered by confidence (highest first).
        Empty list if no signatures match.
    """
    matches: list[MagicMatch] = []

    for magic, offset, fmt_id, description, confidence in _SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            matches.append(MagicMatch(
                format_id=fmt_id,
                description=description,
                confidence=confidence,
            ))

    # Sort by confidence, highest first
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def identify_magic_file(path: Path | str) -> list[MagicMatch]:
    """Identify a file by reading its first 512 bytes.

    Args:
        path: Path to file to identify.

    Returns:
        List of MagicMatch results, or empty if no match / unreadable.
    """
    try:
        p = Path(path)
        # Read only the header — enough for all current signatures
        data = p.read_bytes()[:512]
        return identify_magic(data)
    except (OSError, PermissionError):
        return []


def identify_best_magic(data: bytes) -> MagicMatch | None:
    """Return the single highest-confidence magic match, or None."""
    matches = identify_magic(data)
    return matches[0] if matches else None
