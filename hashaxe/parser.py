# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/parser.py
#  SSH private key file parser supporting OpenSSH, legacy PEM, and PuTTY PPK v2/v3.
#  Auto-fixes CRLF and whitespace issues with zero-copy memoryview slicing.
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
parser.py — SSH private key file parser.

Supports:
  • OpenSSH new format (openssh-key-v1) — Ed25519, RSA, ECDSA, DSS
  • OpenSSH legacy PEM (-----BEGIN RSA/EC/DSA PRIVATE KEY-----)
  • PuTTY PPK v2 (HMAC-SHA1, AES-256-CBC, salted MD5 KDF)
  • PuTTY PPK v3 (HMAC-SHA256, AES-256-CBC, Argon2id KDF)

Auto-fixes:
  • CRLF → LF conversion  (keys from Windows SMB shares)
  • Trailing whitespace stripping

All parsing done with zero-copy memoryview slicing where possible.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

# ── OpenSSH constants ─────────────────────────────────────────────────────────

_SK_MAGIC  = b"openssh-key-v1\x00"     # 15 bytes
_NONE      = b"none"
_BCRYPT    = b"bcrypt"

# Cipher table: name → (key_len, iv_len, block_len, is_aead)
_CIPHER_PARAMS: dict[bytes, tuple[int, int, int, bool]] = {
    b"aes128-ctr":                    (16, 16,  1, False),
    b"aes192-ctr":                    (24, 16,  1, False),
    b"aes256-ctr":                    (32, 16,  1, False),
    b"aes128-cbc":                    (16, 16, 16, False),
    b"aes192-cbc":                    (24, 16, 16, False),
    b"aes256-cbc":                    (32, 16, 16, False),
    b"chacha20-poly1305@openssh.com": (64,  0,  8,  True),
    b"3des-cbc":                      (24,  8,  8, False),
}

# Legacy PEM headers
_LEGACY_HEADERS = {
    b"-----BEGIN RSA PRIVATE KEY-----":     "ssh-rsa",
    b"-----BEGIN EC PRIVATE KEY-----":      "ecdsa",
    b"-----BEGIN DSA PRIVATE KEY-----":     "ssh-dss",
    b"-----BEGIN OPENSSH PRIVATE KEY-----": "openssh",
}

# PPK constants
_PPK_V2_HEADER = b"PuTTY-User-Key-File-2:"
_PPK_V3_HEADER = b"PuTTY-User-Key-File-3:"


# ── Key format enum ───────────────────────────────────────────────────────────

class KeyFormat(Enum):
    OPENSSH_NEW    = auto()   # openssh-key-v1 format
    OPENSSH_LEGACY = auto()   # old PEM RSA/EC/DSA
    PPK_V2         = auto()   # PuTTY v2
    PPK_V3         = auto()   # PuTTY v3


# ── Parsed key dataclass ──────────────────────────────────────────────────────

@dataclass
class ParsedKey:
    """
    Immutable crypto context extracted from a key file.
    Parsed once at startup; workers receive a copy via pickle.
    """

    # Common fields
    fmt:          KeyFormat  = field(default=KeyFormat.OPENSSH_NEW)
    key_type:     str        = ""          # e.g. "ssh-ed25519"
    is_encrypted: bool       = True
    raw_bytes:    bytes      = b""         # original (CRLF-fixed) bytes

    # OpenSSH-specific
    ciphername:   bytes      = b""
    kdfname:      bytes      = b""
    salt:         bytes      = b""
    rounds:       int        = 0
    edata:        bytes      = b""
    tag:          bytes      = b""         # AEAD tag (chacha20-poly1305)
    key_len:      int        = 0
    iv_len:       int        = 0
    block_len:    int        = 0
    is_aead:      bool       = False

    # Legacy PEM-specific
    legacy_iv:    bytes      = b""         # PEM AES-128-CBC IV (from DEK-Info)

    # PPK-specific
    ppk_algorithm:   str     = ""          # e.g. "ed25519"
    ppk_encryption:  str     = ""          # "aes256-cbc" or "none"
    ppk_kdf:         str     = ""          # "argon2id" / "md5" / "none"
    ppk_comment:     str     = ""          # Comment header value (needed for MAC)
    ppk_argon2_salt: bytes   = b""
    ppk_argon2_mem:  int     = 8192
    ppk_argon2_ops:  int     = 13
    ppk_argon2_par:  int     = 1
    ppk_public_blob: bytes   = b""
    ppk_private_blob:bytes   = b""         # encrypted private data
    ppk_mac_data:    bytes   = b""         # expected MAC

    # Unified KDF property
    @property
    def kdf(self) -> str:
        """Return the KDF name regardless of key format."""
        if self.fmt in (KeyFormat.PPK_V2, KeyFormat.PPK_V3):
            return self.ppk_kdf
        if self.kdfname:
            return self.kdfname.decode("ascii", errors="replace")
        return "none"

    # Display helpers
    @property
    def cipher_display(self) -> str:
        if self.fmt in (KeyFormat.OPENSSH_NEW, KeyFormat.OPENSSH_LEGACY):
            return self.ciphername.decode(errors="replace") if self.ciphername else "none"
        return self.ppk_encryption or "none"

    @property
    def kdf_display(self) -> str:
        if self.fmt == KeyFormat.OPENSSH_NEW:
            return self.kdfname.decode(errors="replace") if self.kdfname else "none"
        if self.fmt == KeyFormat.PPK_V3:
            return f"argon2id (mem={self.ppk_argon2_mem}k ops={self.ppk_argon2_ops})"
        if self.fmt == KeyFormat.PPK_V2:
            return "md5 (legacy)"
        return "none"


# ── Low-level binary helpers ──────────────────────────────────────────────────

def _u32(data: memoryview) -> tuple[int, memoryview]:
    if len(data) < 4:
        raise ValueError("Truncated u32 — key data is corrupt or incomplete")
    return int.from_bytes(data[:4], "big"), data[4:]


def _sshstr(data: memoryview) -> tuple[memoryview, memoryview]:
    n, data = _u32(data)
    if n > len(data):
        raise ValueError(f"Truncated sshstr: need {n} bytes, have {len(data)}")
    return data[:n], data[n:]


# ── OpenSSH new-format parser ─────────────────────────────────────────────────

def _parse_openssh_new(raw: bytes) -> ParsedKey:
    """Parse -----BEGIN OPENSSH PRIVATE KEY----- format."""

    start = raw.find(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    end   = raw.find(b"-----END OPENSSH PRIVATE KEY-----")
    if start == -1 or end == -1:
        raise ValueError("Missing OPENSSH PEM envelope markers")

    b64_data = raw[start + 35 : end]
    b64_data = b64_data.replace(b"\n", b"").replace(b" ", b"")

    try:
        decoded = binascii.a2b_base64(b64_data)
    except binascii.Error as exc:
        raise ValueError(f"Base64 decode failed: {exc}") from exc

    if not decoded.startswith(_SK_MAGIC):
        raise ValueError("Bad magic bytes — not an OpenSSH private key")

    mv = memoryview(decoded)[len(_SK_MAGIC):]

    # ── Header fields ──
    try:
        ciphername_mv, mv  = _sshstr(mv)
        kdfname_mv,    mv  = _sshstr(mv)
        kdfoptions_mv, mv  = _sshstr(mv)
        nkeys, mv          = _u32(mv)
    except ValueError as exc:
        raise ValueError(f"Corrupt key header: {exc}") from exc

    if nkeys == 0:
        raise ValueError("Key file contains zero keys")
    if nkeys > 1:
        raise ValueError(f"Multi-key files not supported (found {nkeys} keys)")

    # ── Public key block (extract key_type) ──
    try:
        pubdata_mv, mv     = _sshstr(mv)
        pub_key_type_mv, _ = _sshstr(pubdata_mv)
    except ValueError as exc:
        raise ValueError(f"Corrupt public key block: {exc}") from exc

    # ── Encrypted private blob ──
    try:
        edata_mv, _ = _sshstr(mv)
    except ValueError as exc:
        raise ValueError(f"Corrupt private key blob: {exc}") from exc

    ciphername = bytes(ciphername_mv)
    kdfname    = bytes(kdfname_mv)
    key_type   = bytes(pub_key_type_mv).decode("utf-8", errors="replace")

    pk = ParsedKey(
        fmt       = KeyFormat.OPENSSH_NEW,
        raw_bytes = raw,
        ciphername= ciphername,
        kdfname   = kdfname,
        key_type  = key_type,
        edata     = bytes(edata_mv),
        tag       = b"",
    )

    # ── Unencrypted key ──
    if ciphername == _NONE and kdfname == _NONE:
        pk.is_encrypted = False
        return pk

    pk.is_encrypted = True

    if ciphername not in _CIPHER_PARAMS:
        raise ValueError(
            f"Unsupported cipher: {ciphername!r}\n"
            f"  Supported: {list(_CIPHER_PARAMS.keys())}"
        )
    if kdfname != _BCRYPT:
        raise ValueError(
            f"Unsupported KDF: {kdfname!r}\n"
            f"  Only 'bcrypt' KDF is supported for OpenSSH keys"
        )

    pk.key_len, pk.iv_len, pk.block_len, pk.is_aead = _CIPHER_PARAMS[ciphername]

    # ── KDF options: salt (sshstr) + rounds (u32) ──
    try:
        kdfopts        = memoryview(kdfoptions_mv)
        salt_mv, kdfopts = _sshstr(kdfopts)
        rounds, _      = _u32(kdfopts)
    except ValueError as exc:
        raise ValueError(f"Corrupt KDF options: {exc}") from exc

    pk.salt   = bytes(salt_mv)
    pk.rounds = rounds

    # ── chacha20-poly1305 AEAD tag ──
    if pk.is_aead:
        pk.tag = bytes(edata_mv[-16:])  # trailing 16-byte Poly1305 tag

    return pk


# ── Legacy PEM parser (RSA/EC/DSA pre-OpenSSH-format) ────────────────────────

def _parse_openssh_legacy(raw: bytes, key_type_hint: str) -> ParsedKey:
    """
    Parse old-style PEM keys:
      -----BEGIN RSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: AES-128-CBC,<IV_HEX>

      <base64 data>
      -----END RSA PRIVATE KEY-----
    """
    lines = raw.split(b"\n")

    # Find encryption headers
    is_encrypted = False
    cipher       = b"none"
    iv_hex       = b""

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(b"Proc-Type:") and b"ENCRYPTED" in stripped:
            is_encrypted = True
        if stripped.startswith(b"DEK-Info:"):
            # e.g. DEK-Info: AES-128-CBC,A3F1...
            parts = stripped.split(b":", 1)[1].strip().split(b",")
            cipher = parts[0].strip().lower().replace(b"-", b"")
            if len(parts) > 1:
                iv_hex = parts[1].strip()

    # Extract base64 body (skip headers)
    in_body   = False
    b64_lines = []
    tag_start = next(
        (h for h in _LEGACY_HEADERS if raw.find(h) != -1), None
    )
    if tag_start is None:
        raise ValueError("No recognizable legacy PEM header found")

    begin_marker = tag_start
    end_marker   = begin_marker.replace(b"BEGIN", b"END")

    start = raw.find(begin_marker)
    end   = raw.find(end_marker)
    if start == -1 or end == -1:
        raise ValueError("Incomplete PEM envelope")

    body_section = raw[start + len(begin_marker) : end]
    for line in body_section.split(b"\n"):
        stripped = line.strip()
        if b":" in stripped:  # header line
            continue
        if stripped:
            b64_lines.append(stripped)

    try:
        edata = base64.b64decode(b"".join(b64_lines))
    except Exception as exc:
        raise ValueError(f"Legacy PEM base64 decode failed: {exc}") from exc

    legacy_iv = bytes.fromhex(iv_hex.decode()) if iv_hex else b""

    return ParsedKey(
        fmt         = KeyFormat.OPENSSH_LEGACY,
        raw_bytes   = raw,
        key_type    = key_type_hint,
        is_encrypted= is_encrypted,
        ciphername  = cipher,
        kdfname     = b"md5" if is_encrypted else b"none",
        edata       = edata,
        legacy_iv   = legacy_iv,
        key_len     = 16 if b"128" in cipher else 32,
        iv_len      = 16,
        block_len   = 16,
    )


# ── PPK v2 parser ─────────────────────────────────────────────────────────────

def _parse_ppk_v2(raw: bytes) -> ParsedKey:
    """
    Parse PuTTY PPK version 2 format.

    Format:
      PuTTY-User-Key-File-2: <algorithm>
      Encryption: <aes256-cbc|none>
      Comment: <text>
      Public-Lines: <n>
      <n lines base64 public key>
      Private-Lines: <n>
      <n lines base64 private key (encrypted)>
      Private-MAC: <hex>
    """
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    def _field(name: str) -> str:
        for ln in lines:
            if ln.startswith(name + ":"):
                return ln.split(":", 1)[1].strip()
        raise ValueError(f"PPK v2: missing field '{name}'")

    def _blob(start_marker: str) -> bytes:
        for i, ln in enumerate(lines):
            if ln.startswith(start_marker + ":"):
                count = int(ln.split(":", 1)[1].strip())
                b64   = "".join(lines[i + 1 : i + 1 + count])
                return base64.b64decode(b64)
        raise ValueError(f"PPK v2: missing section '{start_marker}'")

    algorithm  = _field("PuTTY-User-Key-File-2")
    encryption = _field("Encryption")
    comment    = _field("Comment")
    public_b   = _blob("Public-Lines")
    private_b  = _blob("Private-Lines")
    mac_hex    = _field("Private-MAC")

    return ParsedKey(
        fmt              = KeyFormat.PPK_V2,
        raw_bytes        = raw,
        key_type         = f"ppk-{algorithm}",
        is_encrypted     = (encryption != "none"),
        ppk_algorithm    = algorithm,
        ppk_encryption   = encryption,
        ppk_kdf          = "md5" if encryption != "none" else "none",
        ppk_comment      = comment,
        ppk_public_blob  = public_b,
        ppk_private_blob = private_b,
        ppk_mac_data     = bytes.fromhex(mac_hex),
        # AES-256-CBC, key derived via MD5(passphrase+salt)
        key_len   = 32,
        iv_len    = 16,
        block_len = 16,
        ciphername= b"aes256-cbc",
    )


# ── PPK v3 parser ─────────────────────────────────────────────────────────────

def _parse_ppk_v3(raw: bytes) -> ParsedKey:
    """
    Parse PuTTY PPK version 3 format.

    New in v3: Argon2id KDF replaces MD5, HMAC-SHA256 replaces HMAC-SHA1.

    Format:
      PuTTY-User-Key-File-3: <algorithm>
      Encryption: <aes256-cbc|none>
      Comment: <text>
      Public-Lines: <n>
      <base64>
      Key-Derivation: Argon2id
      Argon2-Memory: <kibibytes>
      Argon2-Passes: <iterations>
      Argon2-Parallelism: <threads>
      Argon2-Salt: <hex>
      Private-Lines: <n>
      <base64>
      Private-MAC: <hex>
    """
    text  = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    def _field(name: str, default: str = "") -> str:
        for ln in lines:
            if ln.startswith(name + ":"):
                return ln.split(":", 1)[1].strip()
        if default != "":
            return default
        raise ValueError(f"PPK v3: missing field '{name}'")

    def _blob(start_marker: str) -> bytes:
        for i, ln in enumerate(lines):
            if ln.startswith(start_marker + ":"):
                count = int(ln.split(":", 1)[1].strip())
                b64   = "".join(lines[i + 1 : i + 1 + count])
                return base64.b64decode(b64)
        raise ValueError(f"PPK v3: missing section '{start_marker}'")

    algorithm   = _field("PuTTY-User-Key-File-3")
    encryption  = _field("Encryption")
    comment     = _field("Comment", "")
    public_b    = _blob("Public-Lines")
    private_b   = _blob("Private-Lines")
    mac_hex     = _field("Private-MAC")

    # Argon2 parameters (only present when encrypted)
    argon2_salt = bytes.fromhex(_field("Argon2-Salt", ""))
    argon2_mem  = int(_field("Argon2-Memory",      "8192"))
    argon2_ops  = int(_field("Argon2-Passes",       "13"))
    argon2_par  = int(_field("Argon2-Parallelism",  "1"))
    kdf_name    = _field("Key-Derivation", "none")

    # ARCH-1: Abort early if argon2-cffi not installed for PPK v3 encrypted keys
    if encryption != "none":
        try:
            import argon2  # noqa: F401
        except ImportError:
            raise ValueError(
                "PPK v3 key detected but argon2-cffi is not installed.\n"
                "  This key uses Argon2id KDF which requires the argon2-cffi package.\n"
                "  Install:  pip install hashaxe[ppk-v3]\n"
                "  Or:       pip install argon2-cffi"
            )

    return ParsedKey(
        fmt              = KeyFormat.PPK_V3,
        raw_bytes        = raw,
        key_type         = f"ppk-{algorithm}",
        is_encrypted     = (encryption != "none"),
        ppk_algorithm    = algorithm,
        ppk_encryption   = encryption,
        ppk_kdf          = kdf_name.lower(),
        ppk_comment      = comment,
        ppk_argon2_salt  = argon2_salt,
        ppk_argon2_mem   = argon2_mem,
        ppk_argon2_ops   = argon2_ops,
        ppk_argon2_par   = argon2_par,
        ppk_public_blob  = public_b,
        ppk_private_blob = private_b,
        ppk_mac_data     = bytes.fromhex(mac_hex),
        key_len  = 32,
        iv_len   = 16,
        block_len= 16,
        ciphername= b"aes256-cbc",
    )


# ── Public entry point ────────────────────────────────────────────────────────

def parse_key_file(path: str) -> ParsedKey:
    """
    Detect and parse any supported SSH private key format.

    Supported formats:
      - OpenSSH new format  (-----BEGIN OPENSSH PRIVATE KEY-----)
      - OpenSSH legacy PEM  (-----BEGIN RSA/EC/DSA PRIVATE KEY-----)
      - PuTTY PPK v2        (PuTTY-User-Key-File-2: ...)
      - PuTTY PPK v3        (PuTTY-User-Key-File-3: ...)

    Auto-fixes CRLF line endings.

    Returns:
        ParsedKey with all crypto parameters filled in.

    Raises:
        ValueError: if the file is not a recognised key format or is corrupt.
        FileNotFoundError: if the path does not exist.
    """
    raw = Path(path).read_bytes()

    # ── Normalise line endings (Windows SMB keys) ──
    raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    # ── Detect format ──
    if raw.find(b"-----BEGIN OPENSSH PRIVATE KEY-----") != -1:
        return _parse_openssh_new(raw)

    for header, key_type_hint in _LEGACY_HEADERS.items():
        if header == b"-----BEGIN OPENSSH PRIVATE KEY-----":
            continue
        if raw.find(header) != -1:
            return _parse_openssh_legacy(raw, key_type_hint)

    if raw.startswith(_PPK_V3_HEADER):
        return _parse_ppk_v3(raw)

    if raw.startswith(_PPK_V2_HEADER):
        return _parse_ppk_v2(raw)

    raise ValueError(
        "Unrecognised key format. Expected one of:\n"
        "  • -----BEGIN OPENSSH PRIVATE KEY-----  (modern OpenSSH)\n"
        "  • -----BEGIN RSA/EC/DSA PRIVATE KEY--- (legacy PEM)\n"
        "  • PuTTY-User-Key-File-2: ...           (PuTTY PPK v2)\n"
        "  • PuTTY-User-Key-File-3: ...           (PuTTY PPK v3)\n"
        "Tip: make sure you're using the PRIVATE key, not .pub"
    )
