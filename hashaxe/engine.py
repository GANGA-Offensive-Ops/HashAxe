# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/engine.py
#  Low-level passphrase verification engine for hot-loop cracking.
#  Contains fast-path checkints verification and full parse confirmation.
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
engine.py — Low-level passphrase verification engine.

Contains:
  • try_passphrase()      — fast-path checkints verification (8 bytes only)
  • try_passphrase_full() — full parse confirmation via cryptography library
  • PPK verification      — MAC-based validation for PuTTY keys

The fast-path is the hot loop called millions of times during cracking.
Every microsecond here matters.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_private_key,
)
from cryptography.hazmat.primitives.serialization.ssh import _bcrypt_kdf

try:
    from argon2.low_level import Type as Argon2Type
    from argon2.low_level import hash_secret_raw
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False

from hashaxe.parser import KeyFormat, ParsedKey

# ── Cipher builder ────────────────────────────────────────────────────────────

def _build_cipher(ciphername: bytes, key: bytes, iv: bytes):
    """Return a cryptography Cipher object ready for .decryptor()."""
    if ciphername in (b"aes128-ctr", b"aes192-ctr", b"aes256-ctr"):
        return Cipher(algorithms.AES(key), modes.CTR(iv))
    if ciphername in (b"aes128-cbc", b"aes192-cbc", b"aes256-cbc"):
        return Cipher(algorithms.AES(key), modes.CBC(iv))
    if ciphername == b"3des-cbc":
        return Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    if ciphername == b"chacha20-poly1305@openssh.com":
        # Key layout: first 32B = Poly1305 key material, next 32B = ChaCha20 key
        # Counter = 1 for payload (0 is used for Poly1305 key generation internally)
        nonce = (1).to_bytes(4, "little") + b"\x00" * 12
        return Cipher(algorithms.ChaCha20(key[32:64], nonce), mode=None)
    raise ValueError(f"Unsupported cipher: {ciphername!r}")


# ── OpenSSH checkints fast-path ───────────────────────────────────────────────

def _derive_openssh_key(pk: ParsedKey, password: bytes) -> tuple[bytes, bytes]:
    """
    Run bcrypt-KDF to derive (key_material, iv_material) from password.
    Returns (key, iv) bytes ready for cipher construction.
    """

    seed = _bcrypt_kdf(
        password,
        pk.salt,
        pk.key_len + pk.iv_len,
        pk.rounds,
        True,   # ignore_few_rounds — safe for cracking purposes
    )
    return seed[:pk.key_len], seed[pk.key_len:]


def try_passphrase(pk: ParsedKey, password: bytes) -> bool:
    """
    Fast-path passphrase test.

    For OpenSSH keys: decrypts only the first 8 bytes of edata and
    checks that the two 32-bit checkints are equal.  A wrong password
    produces random garbage → mismatch probability = 1 in 2^32 ≈ negligible.

    For PPK v2/v3: uses MAC verification (more expensive but no alternative).

    Returns True if the password is likely correct (confirm with
    try_passphrase_full() before reporting success).
    """
    if not pk.is_encrypted:
        return True

    try:
        if pk.fmt in (KeyFormat.OPENSSH_NEW, KeyFormat.OPENSSH_LEGACY):
            return _try_openssh(pk, password)
        if pk.fmt in (KeyFormat.PPK_V2, KeyFormat.PPK_V3):
            return _try_ppk(pk, password)
    except Exception:
        pass

    return False


def _try_openssh(pk: ParsedKey, password: bytes) -> bool:
    """OpenSSH fast-path: checkints verification."""
    # Legacy PEM uses MD5 KDF — bypass bcrypt derive entirely
    if pk.fmt == KeyFormat.OPENSSH_LEGACY:
        return _try_openssh_legacy(pk, password, b"", b"")

    key_mat, iv_mat = _derive_openssh_key(pk, password)

    cipher = _build_cipher(pk.ciphername, key_mat, iv_mat)
    dec    = cipher.decryptor()

    if pk.is_aead:
        # chacha20-poly1305: verify Poly1305 MAC before decrypting
        # Fast-path: attempt decryption of first 8 bytes, check checkints
        # (Poly1305 verification would require the full blob — skip for speed,
        # full verification happens in try_passphrase_full())
        needed  = 8
        partial = dec.update(pk.edata[:needed])
    else:
        needed  = max(8, pk.block_len)
        partial = dec.update(pk.edata[:needed])

    ck1 = int.from_bytes(partial[0:4], "big")
    ck2 = int.from_bytes(partial[4:8], "big")
    return ck1 == ck2


def _try_openssh_legacy(pk: ParsedKey, password: bytes,
                         key_mat: bytes, iv_mat: bytes) -> bool:
    """
    Legacy PEM keys use MD5-based key derivation (OpenSSL EVP_BytesToKey).
    Derive AES key from password + IV-salt (MD5), decrypt full edata,
    check PKCS7 padding on the final block.
    """
    # EVP_BytesToKey with MD5, 1 iteration
    salt = pk.legacy_iv[:8]  # first 8 bytes of IV used as salt
    derived = b""
    prev    = b""
    while len(derived) < pk.key_len:
        prev = hashlib.new('md5', prev + password + salt, usedforsecurity=False).digest()
        derived += prev
    key = derived[:pk.key_len]

    cipher = Cipher(algorithms.AES(key), modes.CBC(pk.legacy_iv))
    dec    = cipher.decryptor()

    try:
        # Must decrypt all edata so finalize() can check full CBC padding.
        # PKCS7: the last byte of the final block indicates padding length,
        # and ALL padding bytes must equal that value.
        plaintext = dec.update(pk.edata) + dec.finalize()
        pad = plaintext[-1]
        if not (1 <= pad <= 16):
            return False
        # Validate full PKCS7: all `pad` trailing bytes must equal `pad`
        return all(b == pad for b in plaintext[-pad:])
    except Exception:
        pass
    return False


def _try_ppk(pk: ParsedKey, password: bytes) -> bool:
    """
    PPK MAC verification.
    PPK v2: HMAC-SHA1 over (algorithm + encryption + comment + public + private).
    PPK v3: HMAC-SHA256, same structure, but derived via Argon2.
    """
    try:
        if pk.fmt == KeyFormat.PPK_V2:
            return _try_ppk_v2(pk, password)
        return _try_ppk_v3(pk, password)
    except Exception:
        return False


def _ppk_v2_derive_key(password: bytes) -> bytes:
    """PPK v2 key derivation: two sequential MD5 hashes with sequence numbers."""
    # 32-byte key from two MD5 rounds
    seq0 = hashlib.new('md5', b"\x00\x00\x00\x00" + password, usedforsecurity=False).digest()
    seq1 = hashlib.new('md5', b"\x00\x00\x00\x01" + password, usedforsecurity=False).digest()
    return (seq0 + seq1)[:32]


def _try_ppk_v2(pk: ParsedKey, password: bytes) -> bool:
    """PPK v2: derive AES-256-CBC key via MD5, decrypt, verify HMAC-SHA1."""
    key = _ppk_v2_derive_key(password)
    iv  = b"\x00" * 16  # PPK v2 uses zero IV

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec       = cipher.decryptor()
    plaintext = dec.update(pk.ppk_private_blob) + dec.finalize()

    # Build MAC key: HMAC-SHA1("putty-private-key-file-mac-key" + password)
    mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + password, usedforsecurity=False).digest()

    # MAC covers: algorithm len+data, encryption len+data, comment len+data,
    #             public blob len+data, plaintext private len+data
    def _ppk_str(s: bytes) -> bytes:
        return struct.pack(">I", len(s)) + s

    comment = pk.ppk_comment.encode("utf-8", errors="replace")
    mac_data = (
        _ppk_str(pk.ppk_algorithm.encode())
        + _ppk_str(pk.ppk_encryption.encode())
        + _ppk_str(comment)
        + _ppk_str(pk.ppk_public_blob)
        + _ppk_str(plaintext)
    )

    expected = hmac.new(mac_key, mac_data, hashlib.sha1).digest()
    return hmac.compare_digest(expected, pk.ppk_mac_data)


def _try_ppk_v3(pk: ParsedKey, password: bytes) -> bool:
    """
    PPK v3: Argon2id key derivation, AES-256-CBC decrypt, HMAC-SHA256 verify.
    MAC covers: algorithm + encryption + comment + public + private plaintext
    (each as RFC 4251 length-prefixed strings).
    """
    if not _HAS_ARGON2:
        return False

    # Derive 80 bytes: 32 key + 16 IV + 32 MAC key
    derived = hash_secret_raw(
        secret      = password,
        salt        = pk.ppk_argon2_salt,
        time_cost   = pk.ppk_argon2_ops,
        memory_cost = pk.ppk_argon2_mem,
        parallelism = pk.ppk_argon2_par,
        hash_len    = 80,
        type        = Argon2Type.ID,
    )
    key      = derived[:32]
    iv       = derived[32:48]
    mac_key  = derived[48:80]

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec       = cipher.decryptor()
    plaintext = dec.update(pk.ppk_private_blob) + dec.finalize()

    # HMAC-SHA256 over structured data (same fields as PPK v2, different hash)
    def _ppk_str(s: bytes) -> bytes:
        return struct.pack(">I", len(s)) + s

    comment = pk.ppk_comment.encode("utf-8", errors="replace")
    mac_payload = (
        _ppk_str(pk.ppk_algorithm.encode())
        + _ppk_str(pk.ppk_encryption.encode())
        + _ppk_str(comment)
        + _ppk_str(pk.ppk_public_blob)
        + _ppk_str(plaintext)
    )

    expected = hmac.new(mac_key, mac_payload, hashlib.sha256).digest()
    return hmac.compare_digest(expected, pk.ppk_mac_data)


# ── Full confirmation via official parser ─────────────────────────────────────

def try_passphrase_full(pk: ParsedKey, password: bytes) -> bool:
    """
    Full validation via the cryptography library's official parser.
    Called only after the fast-path finds a candidate — eliminates
    the ~1 in 2^32 false-positive probability.
    """
    if not pk.is_encrypted:
        return True

    try:
        if pk.fmt == KeyFormat.OPENSSH_NEW:
            load_ssh_private_key(pk.raw_bytes, password=password)
            return True

        if pk.fmt == KeyFormat.OPENSSH_LEGACY:
            load_pem_private_key(pk.raw_bytes, password=password)
            return True

        if pk.fmt in (KeyFormat.PPK_V2, KeyFormat.PPK_V3):
            return _try_ppk(pk, password)

    except Exception:
        pass

    return False
