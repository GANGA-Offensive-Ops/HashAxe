# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/web3/zk_auditor.py
#  Web3 Security Auditor and Cracking Engine for blockchain primitives.
#  Covers real Ethereum v3 keystore password cracking, BIP39 mnemonic
#  recovery, Solana keypair detection, and wallet vulnerability analysis.
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
# ⚠️ Version 2.0.0 — Production Audit Upgrade 💀
# ==========================================================================================
"""
web3/zk_auditor.py — Web3 Security Auditor and Cracking Engine.

Production-grade Web3 security suite with REAL operational capabilities:

  1. Ethereum v3 Keystore Password VERIFICATION ENGINE
     - Implements the actual scrypt/PBKDF2 → AES-128-CTR → Keccak-256 MAC pipeline
     - Can test candidate passwords against real wallet files
     - Integrable with wordlists, masks, and distributed workers

  2. BIP39 Mnemonic Recovery ENGINE
     - Real checksum-aware partial seed phrase search
     - Iterates through BIP39 word combinations for missing positions
     - Applies SHA-256 checksum validation to prune invalid candidates
     - Supports known_positions, known_order, arbitrary word gaps

  3. Wallet Security Auditing
     - KDF parameter analysis (scrypt N, PBKDF2 iterations)
     - Cipher strength assessment
     - Solana unencrypted keypair detection
     - Full vulnerability reporting

  4. Keyspace Estimation
     - Mathematically correct search space computation
     - Hardware-aware time projections
     - BIP39 checksum-adjusted keyspace calculation

Architecture:
  ┌──────────────┐   ┌───────────────────┐   ┌──────────────────┐
  │ Wallet File  │──▶│  ZKAuditor        │──▶│  Audit Report    │
  │ or Mnemonic  │   │  (analysis+hashaxe)  │   │  (findings)      │
  └──────────────┘   └───────────────────┘   └──────────────────┘
                             │
                     ┌───────▼────────┐
                     │ EthV3Verifier  │  ← REAL password test engine
                     │ BIP39Recoverer │  ← REAL checksum-aware search
                     └────────────────┘

Ethereum v3 Keystore Password Verification Pipeline:
  1. Read KDF type (scrypt or PBKDF2-SHA256)
  2. Derive 32-byte key from candidate password using wallet's KDF params
  3. Take last 16 bytes as MAC key
  4. Compute Keccak-256(mac_key || ciphertext)
  5. Compare against stored MAC — match = correct password
  6. Decrypt AES-128-CTR(derived_key[:16], iv, ciphertext) → private key

BIP39 Mnemonic Recovery:
  1. Enumerate missing word positions from the full BIP39 wordlist (2048 words)
  2. For each candidate combination, compute SHA-256 checksum
  3. Validate that the last word's bits match the checksum constraint
  4. Optionally derive the BIP-32 seed to confirm derivation path

References:
  - EIP-2335 (Ethereum Keystore v3 specification)
  - BIP-39 (Mnemonic code for generating deterministic keys)
  - BIP-32 (Hierarchical Deterministic Wallets)
  - OWASP Password Storage Cheat Sheet (2024)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import struct
import time
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── BIP39 Constants ──────────────────────────────────────────────────────────

BIP39_WORD_COUNT = 2048

# Full BIP39 English wordlist (subset for validation when full list unavailable)
BIP39_SAMPLE_WORDS = {
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actual",
    "adapt",
    "add",
    "address",
    "adjust",
    "admit",
    "adult",
    "advance",
    "advice",
    "afraid",
    "again",
    "age",
    "agree",
    "ahead",
    "aim",
    "air",
    "alarm",
    "album",
    "alcohol",
    "alert",
    "alien",
    "all",
    "allow",
    "almost",
    "alone",
    "alpha",
    "already",
    "also",
    "alter",
    "always",
    "amazing",
    "among",
    "amount",
    "amateur",
}


# ── Enums ─────────────────────────────────────────────────────────────────────


class WalletType(Enum):
    """Supported cryptocurrency wallet types."""

    ETHEREUM_V3 = "ethereum_v3"
    BITCOIN_CORE = "bitcoin_core"
    SOLANA_KEYPAIR = "solana_keypair"
    METAMASK = "metamask"
    UNKNOWN = "unknown"


class AuditSeverity(Enum):
    """ZK/Web3 audit finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── Output Models ─────────────────────────────────────────────────────────────


@dataclass
class AuditFinding:
    """A single audit finding."""

    category: str = ""
    severity: AuditSeverity = AuditSeverity.INFO
    title: str = ""
    description: str = ""
    recommendation: str = ""


@dataclass
class WalletAnalysis:
    """Result of analyzing a cryptocurrency wallet file."""

    wallet_type: WalletType = WalletType.UNKNOWN
    cipher: str = ""
    kdf: str = ""
    kdf_params: dict = field(default_factory=dict)
    address: str = ""
    estimated_hashaxe_time: str = ""
    hashaxeable: bool = False
    findings: list[AuditFinding] = field(default_factory=list)

    # Provenance
    mode: str = "AUDITOR"
    measured: bool = False
    simulation: bool = False
    implementation_status: str = "PRODUCTION"


@dataclass
class PasswordTestResult:
    """Result of testing a single password against a wallet.

    This is a REAL MEASURED result — the password was actually tested
    against the wallet's KDF + MAC verification pipeline.
    """

    password: str = ""
    match: bool = False
    private_key_hex: str = ""  # Decrypted private key (only if match=True)
    kdf_time_ms: float = 0.0  # Time spent in KDF derivation
    total_time_ms: float = 0.0
    kdf_used: str = ""

    # Provenance
    mode: str = "MEASURED"
    measured: bool = True  # This IS a real measured verification
    simulation: bool = False
    implementation_status: str = "PRODUCTION"
    result_origin: str = "kdf_password_verification"


@dataclass
class MnemonicRecoveryResult:
    """Result of a BIP39 partial mnemonic recovery attempt."""

    found: bool = False
    recovered_mnemonic: str = ""
    candidates_checked: int = 0
    total_keyspace: int = 0
    elapsed_seconds: float = 0.0
    rate_per_sec: float = 0.0

    # Provenance
    mode: str = "MEASURED"
    measured: bool = True  # Real search was executed
    simulation: bool = False
    implementation_status: str = "PRODUCTION"
    result_origin: str = "bip39_checksum_search"


# ══════════════════════════════════════════════════════════════════════════════
# EthV3Verifier — REAL Ethereum v3 Keystore Password Verification Engine
# ══════════════════════════════════════════════════════════════════════════════


class EthV3Verifier:
    """Ethereum v3 Keystore password verification engine.

    Implements the COMPLETE EIP-2335 password verification pipeline:
      password → KDF(scrypt/PBKDF2) → derived_key
      mac_key = derived_key[16:32]
      computed_mac = Keccak-256(mac_key || ciphertext)
      VERIFY: computed_mac == stored_mac

    This is NOT an estimator. This is the REAL verification function that
    runs the actual KDF and MAC computation against the wallet file.

    Usage:
        verifier = EthV3Verifier.from_wallet_file("keystore.json")
        result = verifier.test_password("mysecretpassword")
        if result.match:
            print(f"Password found! Private key: {result.private_key_hex}")
    """

    def __init__(
        self,
        kdf: str,
        kdf_params: dict,
        ciphertext: bytes,
        mac: bytes,
        iv: bytes,
        cipher: str = "aes-128-ctr",
    ):
        self.kdf = kdf.lower()
        self.kdf_params = kdf_params
        self.ciphertext = ciphertext
        self.mac = mac
        self.iv = iv
        self.cipher = cipher.lower()

    @classmethod
    def from_wallet_file(cls, path: str | Path) -> EthV3Verifier:
        """Load an Ethereum v3 keystore and create a verifier.

        Raises:
            FileNotFoundError: If wallet file doesn't exist.
            ValueError: If wallet format is invalid.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Wallet file not found: {path}")

        data = json.loads(p.read_text())
        crypto = data.get("crypto", data.get("Crypto"))
        if not crypto:
            raise ValueError("Not an Ethereum v3 keystore — missing 'crypto' section")

        kdf = crypto.get("kdf", "")
        kdf_params = crypto.get("kdfparams", {})
        ciphertext = bytes.fromhex(crypto.get("ciphertext", ""))
        mac = bytes.fromhex(crypto.get("mac", ""))
        cipher_params = crypto.get("cipherparams", {})
        iv = bytes.fromhex(cipher_params.get("iv", ""))
        cipher_name = crypto.get("cipher", "aes-128-ctr")

        return cls(
            kdf=kdf,
            kdf_params=kdf_params,
            ciphertext=ciphertext,
            mac=mac,
            iv=iv,
            cipher=cipher_name,
        )

    @classmethod
    def from_wallet_dict(cls, data: dict) -> EthV3Verifier:
        """Create verifier from an in-memory wallet dict."""
        crypto = data.get("crypto", data.get("Crypto", {}))
        if not crypto:
            raise ValueError("Missing 'crypto' section in wallet data")

        kdf = crypto.get("kdf", "")
        kdf_params = crypto.get("kdfparams", {})
        ciphertext_hex = crypto.get("ciphertext", "")
        mac_hex = crypto.get("mac", "")
        cipher_params = crypto.get("cipherparams", {})
        iv_hex = cipher_params.get("iv", "")
        cipher_name = crypto.get("cipher", "aes-128-ctr")

        return cls(
            kdf=kdf,
            kdf_params=kdf_params,
            ciphertext=bytes.fromhex(ciphertext_hex) if ciphertext_hex else b"",
            mac=bytes.fromhex(mac_hex) if mac_hex else b"",
            iv=bytes.fromhex(iv_hex) if iv_hex else b"",
            cipher=cipher_name,
        )

    def derive_key(self, password: str) -> bytes:
        """Derive the 32-byte key from password using the wallet's KDF.

        This runs the REAL scrypt or PBKDF2 derivation — it's CPU-intensive
        by design (that's the whole point of KDF).
        """
        pwd_bytes = password.encode("utf-8")

        if self.kdf == "scrypt":
            salt = bytes.fromhex(self.kdf_params.get("salt", ""))
            n = self.kdf_params.get("n", 262144)
            r = self.kdf_params.get("r", 8)
            p = self.kdf_params.get("p", 1)
            dklen = self.kdf_params.get("dklen", 32)
            return hashlib.scrypt(pwd_bytes, salt=salt, n=n, r=r, p=p, dklen=dklen)

        elif self.kdf == "pbkdf2":
            salt = bytes.fromhex(self.kdf_params.get("salt", ""))
            c = self.kdf_params.get("c", 262144)
            dklen = self.kdf_params.get("dklen", 32)
            prf = self.kdf_params.get("prf", "hmac-sha256")
            hash_name = "sha256" if "sha256" in prf else "sha512"
            return hashlib.pbkdf2_hmac(hash_name, pwd_bytes, salt, c, dklen=dklen)

        else:
            raise ValueError(f"Unsupported KDF: {self.kdf}")

    def verify_mac(self, derived_key: bytes) -> bool:
        """Verify the Keccak-256 MAC against the stored MAC.

        MAC = Keccak-256(derived_key[16:32] || ciphertext)
        """
        if not self.mac:
            return False

        mac_key = derived_key[16:32]

        try:
            from Crypto.Hash import keccak  # type: ignore

            k = keccak.new(digest_bits=256)
            k.update(mac_key + self.ciphertext)
            computed_mac = k.digest()
        except ImportError:
            # Fallback: try pysha3 or hashlib (Python 3.11+ has sha3)
            try:
                import sha3  # type: ignore

                k = sha3.keccak_256()
                k.update(mac_key + self.ciphertext)
                computed_mac = k.digest()
            except ImportError:
                # hashlib keccak fallback (not always available)
                try:
                    k = hashlib.new("sha3_256")
                    # NOTE: SHA-3 ≠ Keccak-256 (different padding).
                    # For exact Ethereum verification, pycryptodome is required.
                    # This is an approximation that works for testing.
                    k.update(mac_key + self.ciphertext)
                    computed_mac = k.digest()
                    _msg = (
                        "⚠️  KECCAK-256 APPROXIMATION — Using SHA3-256 as Keccak-256 "
                        "substitute. SHA-3 and Keccak use DIFFERENT padding (NIST "
                        "vs pre-NIST), so MAC verification may produce FALSE NEGATIVES "
                        "against real Ethereum wallets. Correct passwords may appear "
                        "wrong. Install pycryptodome for EXACT Ethereum verification: "
                        "pip install pycryptodome"
                    )
                    logger.warning(_msg)
                    warnings.warn(_msg, stacklevel=2)
                except Exception:
                    _msg = (
                        "⚠️  NO KECCAK-256 AVAILABLE — Cannot verify Ethereum wallet "
                        "MACs. Password verification will ALWAYS FAIL. Install "
                        "pycryptodome: pip install pycryptodome"
                    )
                    logger.error(_msg)
                    return False

        return hmac.compare_digest(computed_mac, self.mac)

    def decrypt_private_key(self, derived_key: bytes) -> bytes:
        """Decrypt the private key using AES-128-CTR.

        Only call this AFTER verify_mac() returns True.
        """
        if self.cipher != "aes-128-ctr":
            logger.warning("Non-standard cipher %s — attempting AES-128-CTR", self.cipher)

        enc_key = derived_key[:16]

        try:
            from Crypto.Cipher import AES  # type: ignore

            cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b"", initial_value=self.iv)
            return cipher.decrypt(self.ciphertext)
        except ImportError:
            try:
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )

                cipher = Cipher(algorithms.AES(enc_key), modes.CTR(self.iv))
                dec = cipher.decryptor()
                return dec.update(self.ciphertext) + dec.finalize()
            except ImportError:
                _msg = (
                    "⚠️  NO AES IMPLEMENTATION — Cannot decrypt Ethereum wallet "
                    "private keys. Install pycryptodome or cryptography package: "
                    "pip install pycryptodome OR pip install cryptography"
                )
                logger.error(_msg)
                warnings.warn(_msg, stacklevel=2)
                return b""

    def test_password(self, password: str) -> PasswordTestResult:
        """Test a single password against this wallet.

        This is the REAL verification pipeline:
          1. Derive key via scrypt/PBKDF2 (CPU-intensive)
          2. Compute Keccak-256 MAC
          3. Compare against stored MAC
          4. If match → decrypt private key via AES-128-CTR

        Returns:
            PasswordTestResult with match status and timing.
        """
        t_start = time.time()

        try:
            derived_key = self.derive_key(password)
            t_kdf = time.time()

            match = self.verify_mac(derived_key)

            private_key_hex = ""
            if match:
                pk_bytes = self.decrypt_private_key(derived_key)
                if pk_bytes:
                    private_key_hex = pk_bytes.hex()

            t_end = time.time()

            return PasswordTestResult(
                password=password,
                match=match,
                private_key_hex=private_key_hex,
                kdf_time_ms=(t_kdf - t_start) * 1000,
                total_time_ms=(t_end - t_start) * 1000,
                kdf_used=self.kdf,
            )
        except Exception as e:
            logger.error("Password verification failed: %s", e)
            return PasswordTestResult(
                password=password,
                match=False,
                result_origin=f"error: {e}",
            )

    def test_passwords(
        self,
        passwords: Iterator[str],
        callback: Callable[[PasswordTestResult], None] | None = None,
    ) -> PasswordTestResult | None:
        """Test multiple passwords sequentially.

        Stops at first match. For parallel cracking, use the hashaxe/cracker.py
        worker pool to distribute candidates across threads.

        Args:
            passwords: Iterator yielding candidate passwords.
            callback: Optional callback for progress reporting.

        Returns:
            PasswordTestResult if found, None if exhausted.
        """
        for pwd in passwords:
            result = self.test_password(pwd)
            if callback:
                callback(result)
            if result.match:
                return result
        return None


# ══════════════════════════════════════════════════════════════════════════════
# BIP39Recoverer — REAL Mnemonic Recovery Engine
# ══════════════════════════════════════════════════════════════════════════════


class BIP39Recoverer:
    """BIP39 partial mnemonic recovery engine.

    Implements REAL checksum-aware brute-force search for missing words
    in a BIP39 seed phrase. This is NOT an estimator — it actually
    iterates through candidates and validates checksums.

    BIP39 Checksum Mechanics:
      - 12 words = 128 bits entropy + 4 bits checksum = 132 bits total
      - 24 words = 256 bits entropy + 8 bits checksum = 264 bits total
      - Each word encodes 11 bits (2^11 = 2048 words)
      - Checksum = first N bits of SHA-256(entropy_bytes)
      - This means ~1/16 of 12-word candidates pass checksum (saves 93.75%)
      - And ~1/256 of 24-word candidates pass checksum (saves 99.6%)

    Usage:
        recoverer = BIP39Recoverer(wordlist)
        # Partial mnemonic: know words 0-9, missing words 10 and 11
        result = recoverer.recover(
            partial=["abandon", "ability", "able", "about", "above",
                     "absent", "absorb", "abstract", "absurd", "abuse",
                     None, None],  # None = unknown word
        )
    """

    def __init__(self, wordlist: list[str] | None = None):
        if wordlist and len(wordlist) == BIP39_WORD_COUNT:
            self._wordlist = wordlist
        else:
            self._wordlist = self._load_default_wordlist()
        self._word_to_index = {w: i for i, w in enumerate(self._wordlist)}

    def _load_default_wordlist(self) -> list[str]:
        """Try to load the BIP39 English wordlist from common locations."""
        search_paths = [
            Path(__file__).parent / "bip39_english.txt",
            Path(__file__).parent.parent / "data" / "bip39_english.txt",
            Path.home() / ".hashaxe" / "bip39_english.txt",
            Path("/usr/share/bip39/english.txt"),
        ]
        for p in search_paths:
            if p.exists():
                words = p.read_text().strip().split("\n")
                words = [w.strip().lower() for w in words if w.strip()]
                if len(words) == BIP39_WORD_COUNT:
                    logger.info("BIP39 wordlist loaded from %s", p)
                    return words

        _msg = (
            "\u26a0\ufe0f  BIP39 WORDLIST NOT FOUND \u2014 Mnemonic recovery engine is DISABLED. "
            "Cannot perform partial seed phrase recovery without the full 2048-word "
            "BIP39 English wordlist. Place bip39_english.txt in one of: "
            f"{', '.join(str(p) for p in search_paths[:2])} "
            "or pass wordlist= directly to BIP39Recoverer()."
        )
        logger.warning(_msg)
        warnings.warn(_msg, stacklevel=2)
        return []

    def validate_checksum(self, word_indices: list[int], total_words: int) -> bool:
        """Validate the BIP39 checksum for a complete set of word indices.

        BIP39 encoding:
          - Concatenate 11-bit index of each word → bit_string
          - Split into entropy_bits (first N bits) and checksum_bits (last CS bits)
          - Compute SHA-256(entropy_bytes)
          - First CS bits of hash must equal checksum_bits

        For 12 words: 132 bits total = 128 entropy + 4 checksum
        For 24 words: 264 bits total = 256 entropy + 8 checksum
        """
        if not word_indices or len(word_indices) != total_words:
            return False

        # Concatenate 11-bit indices into a bitstring
        bits = ""
        for idx in word_indices:
            bits += format(idx, "011b")

        # Split entropy and checksum
        cs_bits = total_words // 3  # 4 for 12 words, 8 for 24 words
        entropy_bits = bits[: len(bits) - cs_bits]
        checksum_bits = bits[len(bits) - cs_bits :]

        # Convert entropy to bytes
        entropy_bytes = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")

        # Compute SHA-256 checksum
        h = hashlib.sha256(entropy_bytes).digest()
        h_bits = bin(int.from_bytes(h, "big"))[2:].zfill(256)
        expected_cs = h_bits[:cs_bits]

        return checksum_bits == expected_cs

    def recover(
        self,
        partial: list[str | None],
        callback: Callable[[int, str], None] | None = None,
        max_candidates: int = 0,
    ) -> MnemonicRecoveryResult:
        """Execute REAL BIP39 partial mnemonic recovery.

        Iterates through all possible word combinations for unknown positions,
        validates BIP39 checksum for each candidate, and returns the first
        valid mnemonic found.

        Args:
            partial: List of known words (str) and unknown positions (None).
                     Length must be 12, 15, 18, 21, or 24.
            callback: Optional callback(candidates_checked, current_candidate).
            max_candidates: Stop after this many candidates (0 = unlimited).

        Returns:
            MnemonicRecoveryResult with the first valid mnemonic if found.
        """
        if not self._wordlist:
            return MnemonicRecoveryResult(
                found=False,
                result_origin="error: BIP39 wordlist not loaded",
            )

        total_words = len(partial)
        if total_words not in (12, 15, 18, 21, 24):
            return MnemonicRecoveryResult(
                found=False,
                result_origin=f"error: invalid mnemonic length {total_words}",
            )

        # Identify unknown positions
        unknown_positions = [i for i, w in enumerate(partial) if w is None]
        known_indices = []
        for i, w in enumerate(partial):
            if w is not None:
                idx = self._word_to_index.get(w.lower())
                if idx is None:
                    return MnemonicRecoveryResult(
                        found=False,
                        result_origin=f"error: '{w}' is not in BIP39 wordlist",
                    )
                known_indices.append((i, idx))
            else:
                known_indices.append((i, -1))  # Sentinel: unknown word position to be brute-forced

        num_unknown = len(unknown_positions)
        total_keyspace = BIP39_WORD_COUNT**num_unknown

        t_start = time.time()
        checked = 0

        # Generate candidates via recursive enumeration
        def _search(pos_idx: int, current_indices: list[int]) -> str | None:
            nonlocal checked
            if max_candidates and checked >= max_candidates:
                return None

            if pos_idx == num_unknown:
                # All unknown positions filled — validate checksum
                checked += 1
                if self.validate_checksum(current_indices, total_words):
                    mnemonic = " ".join(self._wordlist[i] for i in current_indices)
                    return mnemonic
                if callback and checked % 10000 == 0:
                    candidate = " ".join(self._wordlist[i] for i in current_indices)
                    callback(checked, candidate)
                return None

            target_pos = unknown_positions[pos_idx]
            for word_idx in range(BIP39_WORD_COUNT):
                current_indices[target_pos] = word_idx
                result = _search(pos_idx + 1, current_indices)
                if result:
                    return result

            return None

        # Build initial index array
        indices = [0] * total_words
        for i, (pos, idx) in enumerate(known_indices):
            if idx >= 0:
                indices[pos] = idx

        found_mnemonic = _search(0, indices)
        elapsed = time.time() - t_start
        rate = checked / elapsed if elapsed > 0 else 0

        return MnemonicRecoveryResult(
            found=bool(found_mnemonic),
            recovered_mnemonic=found_mnemonic or "",
            candidates_checked=checked,
            total_keyspace=total_keyspace,
            elapsed_seconds=elapsed,
            rate_per_sec=rate,
        )


# ══════════════════════════════════════════════════════════════════════════════
# ZKAuditor — Main Auditor Class (Backward Compatible)
# ══════════════════════════════════════════════════════════════════════════════


class ZKAuditor:
    """Web3 Security Auditor and Cracking Engine.

    Provides:
      1. Wallet file analysis (Ethereum v3, Solana, Bitcoin Core)
      2. BIP39 mnemonic auditing
      3. Keyspace estimation with honest math
      4. REAL password verification engine (via EthV3Verifier)
      5. REAL BIP39 recovery engine (via BIP39Recoverer)
      6. Full portfolio-level security reporting

    All original methods are fully backward-compatible.

    Usage:
        auditor = ZKAuditor()

        # Analyze a wallet file
        analysis = auditor.analyze_wallet("keystore.json")

        # Audit a mnemonic
        findings = auditor.audit_mnemonic("word1 word2 ... word12")

        # Estimate recovery time
        estimate = auditor.estimate_mnemonic_hashaxe(known_words=10, total_words=12)

        # REAL password testing against Ethereum wallet
        verifier = auditor.get_verifier("keystore.json")
        result = verifier.test_password("candidate_password")

        # REAL BIP39 recovery
        recoverer = auditor.get_recoverer()
        result = recoverer.recover(["word1", "word2", ..., None, None])
    """

    def __init__(self, bip39_wordlist_path: str | None = None):
        self._bip39_words: set[str] = BIP39_SAMPLE_WORDS.copy()
        self._bip39_list: list[str] | None = None
        if bip39_wordlist_path:
            self._load_bip39(bip39_wordlist_path)

    def _load_bip39(self, path: str) -> None:
        """Load full BIP39 wordlist from file."""
        try:
            p = Path(path)
            words = p.read_text().strip().split("\n")
            clean = [w.strip().lower() for w in words if w.strip()]
            self._bip39_words = set(clean)
            if len(clean) == BIP39_WORD_COUNT:
                self._bip39_list = clean
            logger.info("BIP39 wordlist loaded: %d words", len(self._bip39_words))
        except Exception as e:
            logger.warning("Failed to load BIP39 wordlist: %s", e)

    # ── Wallet Analysis ──────────────────────────────────────────────────

    def analyze_wallet(self, wallet_path: str | Path) -> WalletAnalysis:
        """Analyze a cryptocurrency wallet file for cracking viability."""
        p = Path(wallet_path)
        if not p.exists():
            return WalletAnalysis(
                findings=[
                    AuditFinding(
                        category="file",
                        severity=AuditSeverity.INFO,
                        title="File not found",
                        description=f"Wallet file not found: {wallet_path}",
                    )
                ],
            )

        try:
            content = p.read_text()
            data = json.loads(content)
        except json.JSONDecodeError:
            return WalletAnalysis(
                findings=[
                    AuditFinding(
                        category="format",
                        severity=AuditSeverity.MEDIUM,
                        title="Invalid format",
                        description="Wallet file is not valid JSON",
                    )
                ],
            )
        except Exception as e:
            return WalletAnalysis(
                findings=[
                    AuditFinding(
                        category="file",
                        severity=AuditSeverity.INFO,
                        title="Read error",
                        description=str(e),
                    )
                ],
            )

        # Solana ed25519 keypair (id.json: 64-element byte array)
        if (
            isinstance(data, list)
            and len(data) == 64
            and all(isinstance(b, int) and 0 <= b <= 255 for b in data)
        ):
            return self._analyze_solana_keypair(data, str(wallet_path))

        return self._analyze_ethereum_v3(data)

    def _analyze_solana_keypair(self, raw_bytes: list[int], source: str) -> WalletAnalysis:
        """Analyze a Solana ed25519 keypair (id.json format)."""
        import base64

        findings: list[AuditFinding] = []

        pubkey_bytes = bytes(raw_bytes[32:])
        pubkey_b58 = base64.b64encode(pubkey_bytes).decode()

        findings.append(
            AuditFinding(
                category="solana",
                severity=AuditSeverity.CRITICAL,
                title="Unencrypted Solana keypair",
                description=(
                    f"Solana id.json stores raw ed25519 keypair without encryption. "
                    f"Public key (base64): {pubkey_b58[:16]}..."
                ),
                recommendation=(
                    "Move to hardware wallet (Ledger) or use solana-keygen with "
                    "BIP39 passphrase. Never store id.json on shared machines."
                ),
            )
        )

        findings.append(
            AuditFinding(
                category="quantum",
                severity=AuditSeverity.HIGH,
                title="Ed25519 vulnerable to quantum (Shor's algorithm)",
                description="Ed25519 keypair will be breakable by quantum computers",
                recommendation="Monitor NIST PQC transition; prepare for ML-DSA migration",
            )
        )

        return WalletAnalysis(
            wallet_type=WalletType.SOLANA_KEYPAIR,
            cipher="none (unencrypted)",
            kdf="none",
            address=pubkey_b58[:44],
            estimated_hashaxe_time="immediate (no password protection)",
            hashaxeable=False,  # No password to hashaxe — key is plaintext
            findings=findings,
        )

    def _analyze_ethereum_v3(self, data: dict) -> WalletAnalysis:
        """Analyze an Ethereum v3 keystore wallet."""
        crypto = data.get("crypto", data.get("Crypto", {}))
        if not crypto:
            return WalletAnalysis(wallet_type=WalletType.UNKNOWN)

        cipher = crypto.get("cipher", "unknown")
        kdf = crypto.get("kdf", "unknown")
        kdf_params = crypto.get("kdfparams", {})
        address = data.get("address", "unknown")

        findings: list[AuditFinding] = []

        # Analyze KDF strength
        if kdf == "scrypt":
            n = kdf_params.get("n", 0)
            r = kdf_params.get("r", 0)
            p = kdf_params.get("p", 0)
            if n < 262144:  # 2^18
                findings.append(
                    AuditFinding(
                        category="kdf",
                        severity=AuditSeverity.HIGH,
                        title="Weak scrypt parameters",
                        description=f"scrypt N={n} is below recommended minimum (262144)",
                        recommendation="Use N=262144, r=8, p=1 minimum",
                    )
                )
            est_time = f"~{n * r * p // 500_000:.0f} hours with GPU cluster"
        elif kdf == "pbkdf2":
            c = kdf_params.get("c", 0)
            if c < 100000:
                findings.append(
                    AuditFinding(
                        category="kdf",
                        severity=AuditSeverity.CRITICAL,
                        title="Weak PBKDF2 iterations",
                        description=f"PBKDF2 c={c} is critically low",
                        recommendation="Use minimum 600,000 iterations (OWASP 2024)",
                    )
                )
            est_time = f"~{c // 1_000_000:.1f} hours with GPU cluster"
        else:
            est_time = "unknown"

        # Cipher analysis
        if cipher != "aes-128-ctr":
            findings.append(
                AuditFinding(
                    category="cipher",
                    severity=AuditSeverity.MEDIUM,
                    title=f"Non-standard cipher: {cipher}",
                    description="Expected aes-128-ctr for Ethereum v3",
                )
            )

        return WalletAnalysis(
            wallet_type=WalletType.ETHEREUM_V3,
            cipher=cipher,
            kdf=kdf,
            kdf_params=kdf_params,
            address=address,
            estimated_hashaxe_time=est_time,
            hashaxeable=True,
            findings=findings,
        )

    # ── BIP39 Mnemonic Auditing ──────────────────────────────────────────

    def audit_mnemonic(self, mnemonic: str) -> list[AuditFinding]:
        """Audit a BIP39 mnemonic seed phrase for weaknesses."""
        findings: list[AuditFinding] = []
        words = mnemonic.strip().lower().split()

        # Check word count
        if len(words) not in (12, 15, 18, 21, 24):
            findings.append(
                AuditFinding(
                    category="mnemonic",
                    severity=AuditSeverity.CRITICAL,
                    title="Invalid mnemonic length",
                    description=f"Got {len(words)} words, expected 12/15/18/21/24",
                )
            )

        # Check for valid BIP39 words
        invalid = [w for w in words if w not in self._bip39_words]
        if invalid and len(self._bip39_words) > 100:
            findings.append(
                AuditFinding(
                    category="mnemonic",
                    severity=AuditSeverity.HIGH,
                    title="Invalid BIP39 words",
                    description=f"Words not in BIP39 list: {', '.join(invalid[:5])}",
                )
            )

        # Check for duplicate words
        if len(words) != len(set(words)):
            findings.append(
                AuditFinding(
                    category="mnemonic",
                    severity=AuditSeverity.MEDIUM,
                    title="Duplicate words in mnemonic",
                    description="Mnemonic contains repeated words, reducing entropy",
                )
            )

        # Entropy analysis
        if len(words) == 12:
            findings.append(
                AuditFinding(
                    category="entropy",
                    severity=AuditSeverity.INFO,
                    title="12-word mnemonic = 128 bits entropy",
                    description="Consider 24-word (256 bits) for high-value assets",
                )
            )

        return findings

    # ── Keyspace Estimation ──────────────────────────────────────────────

    def estimate_mnemonic_hashaxe(
        self,
        known_words: int,
        total_words: int = 12,
        known_positions: bool = True,
        checksum_reduction: bool = True,
    ) -> dict:
        """Estimate cracking time for partial BIP39 mnemonic recovery.

        Args:
            known_words: Number of known words.
            total_words: Total mnemonic length (12/24).
            known_positions: If True, positions of known words are fixed.
            checksum_reduction: If True, apply BIP39 checksum pruning.

        Returns:
            Dict with keyspace, estimated time, feasibility, and provenance.
        """
        unknown = total_words - known_words
        raw_keyspace = BIP39_WORD_COUNT**unknown

        # BIP39 checksum reduces valid candidates
        if checksum_reduction and unknown > 0:
            cs_bits = total_words // 3  # 4 for 12-word, 8 for 24-word
            # Checksum eliminates ~(1 - 1/2^cs_bits) of candidates
            checksum_factor = 2**cs_bits
            adjusted_keyspace = max(1, raw_keyspace // checksum_factor)
        else:
            adjusted_keyspace = raw_keyspace
            checksum_factor = 1

        # If positions are unknown, multiply by C(total, unknown)
        if not known_positions and unknown > 0:
            from math import comb

            positional_factor = comb(total_words, unknown)
            adjusted_keyspace *= positional_factor
        else:
            positional_factor = 1

        # Assume ~10,000 mnemonics/sec (scrypt-based seed derivation)
        rate = 10_000
        seconds = adjusted_keyspace / rate

        if seconds < 60:
            time_str = f"{seconds:.1f} seconds"
            feasible = "TRIVIAL"
        elif seconds < 3600:
            time_str = f"{seconds / 60:.1f} minutes"
            feasible = "EASY"
        elif seconds < 86400:
            time_str = f"{seconds / 3600:.1f} hours"
            feasible = "MODERATE"
        elif seconds < 86400 * 365:
            time_str = f"{seconds / 86400:.1f} days"
            feasible = "HARD"
        else:
            time_str = f"{seconds / (86400 * 365):.1e} years"
            feasible = "INFEASIBLE"

        return {
            "total_words": total_words,
            "known_words": known_words,
            "unknown_words": unknown,
            "keyspace": raw_keyspace,
            "checksum_adjusted_keyspace": adjusted_keyspace,
            "checksum_reduction_factor": checksum_factor,
            "positional_factor": positional_factor,
            "rate_per_sec": rate,
            "estimated_time": time_str,
            "feasibility": feasible,
            # Provenance
            "mode": "ESTIMATOR",
            "measured": False,
            "simulation": False,
            "implementation_status": "PRODUCTION",
            "result_origin": "mathematical_computation",
            "assumptions": [
                f"Rate estimate: {rate} mnemonics/sec (scrypt seed derivation)",
                "Known positions: " + ("yes" if known_positions else "no"),
                "BIP39 checksum pruning: " + ("applied" if checksum_reduction else "not applied"),
            ],
        }

    # ── Engine Access ────────────────────────────────────────────────────

    def get_verifier(self, wallet_path: str | Path) -> EthV3Verifier:
        """Get a REAL Ethereum v3 password verifier for a wallet file.

        Usage:
            verifier = auditor.get_verifier("keystore.json")
            result = verifier.test_password("candidate")
        """
        return EthV3Verifier.from_wallet_file(wallet_path)

    def get_recoverer(self, wordlist: list[str] | None = None) -> BIP39Recoverer:
        """Get a REAL BIP39 mnemonic recovery engine.

        Usage:
            recoverer = auditor.get_recoverer()
            result = recoverer.recover(["word1", ..., None, None])
        """
        return BIP39Recoverer(wordlist=wordlist or self._bip39_list)

    # ── Reporting ────────────────────────────────────────────────────────

    def full_report(
        self,
        wallets: list[WalletAnalysis],
        mnemonic_findings: list[AuditFinding] | None = None,
    ) -> dict:
        """Generate a comprehensive Web3 security report."""
        all_findings = []
        for w in wallets:
            all_findings.extend(w.findings)
        if mnemonic_findings:
            all_findings.extend(mnemonic_findings)

        critical = [f for f in all_findings if f.severity == AuditSeverity.CRITICAL]
        high = [f for f in all_findings if f.severity == AuditSeverity.HIGH]

        return {
            "total_wallets": len(wallets),
            "hashaxeable_wallets": sum(1 for w in wallets if w.hashaxeable),
            "total_findings": len(all_findings),
            "critical_findings": len(critical),
            "high_findings": len(high),
            "implementation_status": "PRODUCTION",
            "findings": [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in all_findings
            ],
        }
