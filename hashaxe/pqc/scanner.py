# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/pqc/scanner.py
#  Post-Quantum Cryptography vulnerability scanner for crypto assets.
#  Production-grade classifier with robust algorithm parsing, family inference,
#  logical/physical qubit estimation, and literature-backed risk assessment.
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
pqc/scanner.py — Post-Quantum Cryptography vulnerability scanner.

Production-grade crypto inventory and migration risk classifier.
Analyzes cryptographic assets (SSH keys, hashes, TLS certificates, algorithm
names) and assesses their vulnerability to quantum attacks using structured
heuristics derived from NIST PQC standards and published research.

Capabilities:
  - Robust algorithm name parsing and normalization
  - Crypto family inference (RSA, ECC, DH, AES, SHA, KDF)
  - Separate risk analysis for Shor's vs Grover's attack vectors
  - Logical and physical qubit estimation (literature-based ranges)
  - Confidence scoring and reference basis citation
  - SSH key scanning (PEM/OpenSSH format detection)
  - Hash string analysis and quantum risk classification
  - X.509 certificate scanning (with cryptography package or PEM fallback)
  - Full portfolio-level aggregate reporting

Risk Categories:
  QUANTUM_SAFE:       Uses PQC algorithms (ML-KEM, SLH-DSA, ML-DSA) or
                      symmetric primitives with sufficient post-quantum margin
  QUANTUM_VULNERABLE: Uses classical public-key crypto breakable by Shor's
  QUANTUM_PARTIAL:    Symmetric/hash primitives weakened but not broken by Grover's
  QUANTUM_UNKNOWN:    Algorithm not recognized — manual review required

Timeline Ranges (based on Q-Day projections and published estimates):
  IMMEDIATE (2025-2028):  RSA-1024, DH-1024, MD5, SHA-1
  NEAR_TERM (2028-2032):  RSA-2048, ECDSA P-256, ECDH, Ed25519
  MEDIUM_TERM (2032-2040): RSA-4096, ECDSA P-384, Ed448
  LONG_TERM (2040+):      AES-128, SHA-256, bcrypt (Grover's √N only)
  POST_QUANTUM_SAFE:      AES-256, SHA-3, Argon2, ML-KEM, ML-DSA, SLH-DSA

References:
  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  - NIST IR 8547 "Transition to Post-Quantum Cryptography Standards"
  - Gidney & Ekerå (2021) "How to factor 2048 bit RSA integers in 8 hours
    using 20 million noisy qubits" — arXiv:1905.09749
  - Amy et al. (2016) "Estimating the cost of generic quantum pre-image
    attacks on SHA-2 and SHA-3"
  - Roetteler et al. (2017) "Quantum resource estimates for computing
    elliptic curve discrete logarithms" — arXiv:1706.06752
  - Grassl et al. (2016) "Applying Grover's algorithm to AES"
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────────────


class QuantumRisk(Enum):
    """Quantum vulnerability risk level."""

    SAFE = "QUANTUM_SAFE"
    VULNERABLE = "QUANTUM_VULNERABLE"
    PARTIAL = "QUANTUM_PARTIAL"
    UNKNOWN = "QUANTUM_UNKNOWN"


class RiskTimeline(Enum):
    """Estimated timeline until quantum break becomes practical."""

    IMMEDIATE = "2025-2028"
    NEAR_TERM = "2028-2032"
    MEDIUM_TERM = "2032-2040"
    LONG_TERM = "2040+"
    SAFE = "Post-Quantum Safe"


class CryptoFamily(Enum):
    """Cryptographic algorithm family classification."""

    RSA = "rsa"
    ECC = "ecc"  # ECDSA, ECDH, EdDSA
    DH = "dh"  # Diffie-Hellman, DSA
    AES = "aes"  # Symmetric block cipher
    SYMMETRIC = "symmetric"  # Other symmetric (ChaCha20, etc.)
    SHA = "sha"  # Hash functions
    KDF = "kdf"  # Password-hashing / key-derivation
    PQC = "pqc"  # Post-quantum algorithms
    UNKNOWN = "unknown"


class AttackVector(Enum):
    """Quantum attack classification."""

    SHORS_FACTORING = "Shor's Algorithm (Integer Factorization)"
    SHORS_ECDLP = "Shor's Algorithm (Elliptic Curve Discrete Log)"
    SHORS_DLP = "Shor's Algorithm (Discrete Logarithm)"
    GROVERS_KEY_SEARCH = "Grover's Algorithm (Symmetric Key Search)"
    GROVERS_PREIMAGE = "Grover's Algorithm (Hash Pre-image)"
    GROVERS_COLLISION = "Grover's Algorithm (Birthday Bound Reduction)"
    CLASSICAL_PLUS_GROVER = "Classical Weakness + Grover's Acceleration"
    MEMORY_HARD_RESISTANT = "Memory-hard: quantum advantage minimal"
    NONE_KNOWN = "No known quantum attack"


# ── Output Models ─────────────────────────────────────────────────────────────


@dataclass
class ScanResult:
    """Result of scanning a single cryptographic asset.

    Every field is explicitly documented for provenance clarity.
    """

    # ── Identity ──
    asset_type: str = ""  # "ssh_key", "hash", "certificate", "algorithm"
    algorithm: str = ""  # Raw input algorithm name
    normalized_algorithm: str = ""  # Parsed/normalized canonical form
    family: CryptoFamily = CryptoFamily.UNKNOWN
    key_size: int = 0  # Key/hash size in bits (0 if N/A)

    # ── Risk Assessment ──
    risk: QuantumRisk = QuantumRisk.UNKNOWN
    attack_vector: AttackVector = AttackVector.NONE_KNOWN
    timeline: RiskTimeline = RiskTimeline.SAFE

    # ── Qubit Estimates ──
    logical_qubits_estimate: int = 0  # Ideal error-free qubits needed
    physical_qubits_estimate: str = ""  # Estimated range with error correction overhead

    # ── Provenance ──
    mode: str = "CLASSIFIER"
    measured: bool = False  # This is classification, never measured
    simulation: bool = False  # This is classification, never simulated
    implementation_status: str = "PRODUCTION"
    result_origin: str = "literature_heuristic"
    confidence: str = "HIGH"  # HIGH / MEDIUM / LOW
    rationale: str = ""  # Why this risk level
    recommendation: str = ""
    references_basis: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    details: str = ""

    # Backward compatibility alias
    @property
    def qubits_needed(self) -> int:
        """Backward-compatible alias for logical_qubits_estimate."""
        return self.logical_qubits_estimate

    @property
    def risk_score(self) -> int:
        """Numeric risk score (0=safe, 100=critical).

        Combines risk level with timeline proximity for a single scalar.
        """
        base_scores = {
            QuantumRisk.SAFE: 0,
            QuantumRisk.PARTIAL: 40,
            QuantumRisk.UNKNOWN: 50,
            QuantumRisk.VULNERABLE: 90,
        }
        timeline_multipliers = {
            RiskTimeline.SAFE: 0.0,
            RiskTimeline.LONG_TERM: 0.5,
            RiskTimeline.MEDIUM_TERM: 0.75,
            RiskTimeline.NEAR_TERM: 0.9,
            RiskTimeline.IMMEDIATE: 1.0,
        }
        base = base_scores.get(self.risk, 50)
        mul = timeline_multipliers.get(self.timeline, 0.5)
        return int(base * mul)


# ── Algorithm Knowledge Base ─────────────────────────────────────────────────
# Each entry is a structured record with full provenance, not a flat dict.


@dataclass
class _AlgoRecord:
    """Internal structured record for a known algorithm."""

    canonical: str
    family: CryptoFamily
    risk: QuantumRisk
    timeline: RiskTimeline
    attack: AttackVector
    logical_qubits: int
    physical_qubits_range: str
    key_size: int
    confidence: str
    rationale: str
    recommendation: str
    references: list[str]
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _build_algo_db() -> dict[str, _AlgoRecord]:
    """Build the structured algorithm knowledge base.

    Sources:
      - Gidney & Ekerå 2021 (RSA factoring resource estimates)
      - Roetteler et al. 2017 (ECC discrete log resource estimates)
      - Grassl et al. 2016 (Grover's on AES)
      - Amy et al. 2016 (Grover's on SHA-2/SHA-3)
      - NIST SP 800-208, FIPS 203/204/205
    """
    db: dict[str, _AlgoRecord] = {}

    # ── RSA Family (Shor's Algorithm — Integer Factoring) ────────────────
    for bits, tl, logical_q, phys_range in [
        (1024, RiskTimeline.IMMEDIATE, 2048, "~4M noisy qubits"),
        (2048, RiskTimeline.NEAR_TERM, 4096, "~20M noisy qubits (Gidney & Ekerå 2021)"),
        (3072, RiskTimeline.NEAR_TERM, 6144, "~30M noisy qubits (extrapolated)"),
        (4096, RiskTimeline.MEDIUM_TERM, 8192, "~40M noisy qubits (extrapolated)"),
        (8192, RiskTimeline.MEDIUM_TERM, 16384, "~80M noisy qubits (extrapolated)"),
    ]:
        db[f"rsa-{bits}"] = _AlgoRecord(
            canonical=f"rsa-{bits}",
            family=CryptoFamily.RSA,
            risk=QuantumRisk.VULNERABLE,
            timeline=tl,
            attack=AttackVector.SHORS_FACTORING,
            logical_qubits=logical_q,
            physical_qubits_range=phys_range,
            key_size=bits,
            confidence="HIGH",
            rationale=(
                f"RSA-{bits} relies on integer factoring hardness. "
                f"Shor's algorithm factors {bits}-bit semiprimes in polynomial time "
                f"on a sufficiently large fault-tolerant quantum computer."
            ),
            recommendation=f"Migrate to ML-KEM-{'768' if bits <= 2048 else '1024'} (FIPS 203)",
            references=[
                "Gidney & Ekerå (2021) arXiv:1905.09749",
                "NIST IR 8547",
                "NIST FIPS 203 (ML-KEM)",
            ],
            assumptions=[
                "Assumes fault-tolerant quantum computer with surface code error correction",
                f"Physical qubit estimate based on {bits}-bit modulus factoring",
            ],
        )

    # ── ECC Family (Shor's Algorithm — ECDLP) ───────────────────────────
    ecc_entries = [
        ("ecdsa-p256", 256, RiskTimeline.NEAR_TERM, 2330, "~4.7M noisy qubits (Roetteler 2017)"),
        ("ecdsa-p384", 384, RiskTimeline.MEDIUM_TERM, 3484, "~7M noisy qubits (extrapolated)"),
        ("ecdsa-p521", 521, RiskTimeline.MEDIUM_TERM, 4700, "~9.5M noisy qubits (extrapolated)"),
        ("ed25519", 256, RiskTimeline.NEAR_TERM, 1700, "~3.4M noisy qubits (Roetteler 2017)"),
        ("ed448", 448, RiskTimeline.MEDIUM_TERM, 2500, "~5M noisy qubits (extrapolated)"),
        ("x25519", 256, RiskTimeline.NEAR_TERM, 1700, "~3.4M noisy qubits"),
        ("x448", 448, RiskTimeline.MEDIUM_TERM, 2500, "~5M noisy qubits"),
        ("ecdh-p256", 256, RiskTimeline.NEAR_TERM, 2330, "~4.7M noisy qubits"),
        ("ecdh-p384", 384, RiskTimeline.MEDIUM_TERM, 3484, "~7M noisy qubits"),
    ]
    for name, bits, tl, lq, pq in ecc_entries:
        db[name] = _AlgoRecord(
            canonical=name,
            family=CryptoFamily.ECC,
            risk=QuantumRisk.VULNERABLE,
            timeline=tl,
            attack=AttackVector.SHORS_ECDLP,
            logical_qubits=lq,
            physical_qubits_range=pq,
            key_size=bits,
            confidence="HIGH",
            rationale=(
                f"{name} relies on the Elliptic Curve Discrete Logarithm Problem. "
                f"Shor's algorithm solves ECDLP on a {bits}-bit curve in polynomial time."
            ),
            recommendation="Migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
            references=[
                "Roetteler et al. (2017) arXiv:1706.06752",
                "NIST IR 8547",
                "NIST FIPS 204 (ML-DSA)",
            ],
        )

    # ── DH / DSA Family (Shor's — DLP) ──────────────────────────────────
    for bits, tl, lq, pq in [
        (1024, RiskTimeline.IMMEDIATE, 2048, "~4M noisy qubits"),
        (2048, RiskTimeline.NEAR_TERM, 4096, "~20M noisy qubits"),
        (3072, RiskTimeline.NEAR_TERM, 6144, "~30M noisy qubits"),
    ]:
        for prefix in ("dh", "dsa"):
            db[f"{prefix}-{bits}"] = _AlgoRecord(
                canonical=f"{prefix}-{bits}",
                family=CryptoFamily.DH,
                risk=QuantumRisk.VULNERABLE,
                timeline=tl,
                attack=AttackVector.SHORS_DLP,
                logical_qubits=lq,
                physical_qubits_range=pq,
                key_size=bits,
                confidence="HIGH",
                rationale=(
                    f"{prefix.upper()}-{bits} relies on the Discrete Logarithm Problem. "
                    f"Shor's algorithm solves DLP in polynomial time."
                ),
                recommendation="Migrate to ML-KEM (FIPS 203) for key exchange",
                references=["Shor (1994)", "NIST IR 8547"],
            )

    # ── Symmetric Ciphers (Grover's — Key Search) ────────────────────────
    for bits, risk, tl, lq, pq, rec in [
        (
            128,
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            2953,
            "~6K noisy qubits (Grassl 2016)",
            "Upgrade to AES-256 for post-quantum margin",
        ),
        (
            192,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            4449,
            "~9K noisy qubits",
            "Already provides 96-bit post-quantum security",
        ),
        (
            256,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            6681,
            "~13K noisy qubits (Grassl 2016)",
            "Already quantum-safe (128-bit post-quantum margin)",
        ),
    ]:
        db[f"aes-{bits}"] = _AlgoRecord(
            canonical=f"aes-{bits}",
            family=CryptoFamily.AES,
            risk=risk,
            timeline=tl,
            attack=AttackVector.GROVERS_KEY_SEARCH,
            logical_qubits=lq,
            physical_qubits_range=pq,
            key_size=bits,
            confidence="HIGH",
            rationale=(
                f"AES-{bits}: Grover's algorithm reduces effective key strength from "
                f"{bits} to {bits // 2} bits. {'Insufficient' if bits == 128 else 'Sufficient'} "
                f"post-quantum security margin."
            ),
            recommendation=rec,
            references=["Grassl et al. (2016)", "NIST SP 800-131A Rev.2"],
            limitations=[
                "Grover's requires sequential oracle queries — parallelization is limited"
            ],
        )

    # ChaCha20 / Salsa20
    for name in ("chacha20", "chacha20-poly1305", "salsa20"):
        db[name] = _AlgoRecord(
            canonical=name,
            family=CryptoFamily.SYMMETRIC,
            risk=QuantumRisk.SAFE,
            timeline=RiskTimeline.SAFE,
            attack=AttackVector.GROVERS_KEY_SEARCH,
            logical_qubits=6681,
            physical_qubits_range="~13K noisy qubits",
            key_size=256,
            confidence="HIGH",
            rationale="256-bit symmetric cipher. Grover's reduces to 128-bit — still safe.",
            recommendation="Already quantum-safe",
            references=["NIST SP 800-131A"],
        )

    # ── Hash Functions (Grover's — Pre-image & Collision) ────────────────
    hash_entries = [
        (
            "md5",
            128,
            QuantumRisk.VULNERABLE,
            RiskTimeline.IMMEDIATE,
            640,
            "~1.3K noisy qubits",
            AttackVector.CLASSICAL_PLUS_GROVER,
            "MD5 is already classically broken (collisions). Grover's accelerates pre-image.",
            "Migrate to SHA-3-256 or SHAKE256",
        ),
        (
            "sha1",
            160,
            QuantumRisk.VULNERABLE,
            RiskTimeline.IMMEDIATE,
            800,
            "~1.6K noisy qubits",
            AttackVector.CLASSICAL_PLUS_GROVER,
            "SHA-1 is classically broken (SHAttered 2017). Grover's accelerates pre-image.",
            "Migrate to SHA-3-256",
        ),
        (
            "sha224",
            224,
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            1500,
            "~3K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-224: 112-bit post-quantum pre-image security via Grover's.",
            "Consider SHA-3-256 for long-term safety",
        ),
        (
            "sha256",
            256,
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            2500,
            "~5K noisy qubits (Amy 2016)",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-256: Grover's reduces pre-image to 128-bit — still computationally infeasible.",
            "Consider SHA-3-256 for long-term safety",
        ),
        (
            "sha384",
            384,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            3500,
            "~7K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-384: 192-bit post-quantum pre-image security. Quantum-safe.",
            "Already quantum-safe",
        ),
        (
            "sha512",
            512,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            4500,
            "~9K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-512: 256-bit post-quantum pre-image security. Quantum-safe.",
            "Already quantum-safe",
        ),
        (
            "sha3-256",
            256,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            2500,
            "~5K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-3-256: 128-bit post-quantum security. Sponge construction resists quantum well.",
            "Already quantum-safe",
        ),
        (
            "sha3-512",
            512,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            4500,
            "~9K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "SHA-3-512: 256-bit post-quantum security. Quantum-safe by design.",
            "Already quantum-safe",
        ),
        (
            "blake2b",
            512,
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            4500,
            "~9K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "BLAKE2b-512: 256-bit post-quantum security.",
            "Already quantum-safe",
        ),
        (
            "blake2s",
            256,
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            2500,
            "~5K noisy qubits",
            AttackVector.GROVERS_PREIMAGE,
            "BLAKE2s-256: 128-bit post-quantum pre-image security.",
            "Consider longer output for safety margin",
        ),
    ]
    for name, bits, risk, tl, lq, pq, atk, rat, rec in hash_entries:
        db[name] = _AlgoRecord(
            canonical=name,
            family=CryptoFamily.SHA,
            risk=risk,
            timeline=tl,
            attack=atk,
            logical_qubits=lq,
            physical_qubits_range=pq,
            key_size=bits,
            confidence="HIGH" if name in ("md5", "sha1", "sha256", "sha3-256") else "MEDIUM",
            rationale=rat,
            recommendation=rec,
            references=["Amy et al. (2016)", "NIST SP 800-131A"],
        )

    # ── KDF / Password Hashing (Memory-hard resistance) ──────────────────
    kdf_entries = [
        (
            "bcrypt",
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            5000,
            "~10K+ noisy qubits",
            "bcrypt: Memory-hard design limits Grover's parallelization advantage.",
            "Increase cost factor; consider Argon2id for new deployments",
        ),
        (
            "scrypt",
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            5000,
            "~10K+ noisy qubits",
            "scrypt: Memory-hard. Quantum speedup limited by sequential memory access.",
            "Consider Argon2id for new deployments",
        ),
        (
            "argon2",
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            10000,
            "~20K+ noisy qubits",
            "Argon2id: Memory-hard, time-hard. Quantum advantage minimal by design.",
            "Already quantum-resistant. Use Argon2id variant.",
        ),
        (
            "argon2id",
            QuantumRisk.SAFE,
            RiskTimeline.SAFE,
            10000,
            "~20K+ noisy qubits",
            "Argon2id: Maximum resistance to both GPU and quantum attacks.",
            "Already quantum-resistant — recommended for all new password hashing",
        ),
        (
            "pbkdf2",
            QuantumRisk.PARTIAL,
            RiskTimeline.LONG_TERM,
            3000,
            "~6K noisy qubits",
            "PBKDF2: Not memory-hard. Grover's provides √N speedup on iteration count.",
            "Migrate to Argon2id. Minimum 600,000 iterations (OWASP 2024).",
        ),
    ]
    for name, risk, tl, lq, pq, rat, rec in kdf_entries:
        db[name] = _AlgoRecord(
            canonical=name,
            family=CryptoFamily.KDF,
            risk=risk,
            timeline=tl,
            attack=(
                AttackVector.MEMORY_HARD_RESISTANT
                if "argon" in name
                else AttackVector.GROVERS_KEY_SEARCH
            ),
            logical_qubits=lq,
            physical_qubits_range=pq,
            key_size=0,
            confidence="MEDIUM",
            rationale=rat,
            recommendation=rec,
            references=["NIST SP 800-63B", "OWASP Password Storage Cheat Sheet (2024)"],
            limitations=[
                "KDF quantum resistance depends on parameter tuning (cost factor, memory)"
            ],
        )

    # ── Unix crypt variants ──────────────────────────────────────────────
    db["descrypt"] = _AlgoRecord(
        canonical="descrypt",
        family=CryptoFamily.KDF,
        risk=QuantumRisk.VULNERABLE,
        timeline=RiskTimeline.IMMEDIATE,
        attack=AttackVector.CLASSICAL_PLUS_GROVER,
        logical_qubits=500,
        physical_qubits_range="~1K noisy qubits",
        key_size=56,
        confidence="HIGH",
        rationale="DES-based crypt: 56-bit effective key. Classically broken, trivially quantum-breakable.",
        recommendation="Migrate to yescrypt or Argon2id immediately",
        references=["NIST SP 800-131A"],
    )
    db["md5crypt"] = _AlgoRecord(
        canonical="md5crypt",
        family=CryptoFamily.KDF,
        risk=QuantumRisk.VULNERABLE,
        timeline=RiskTimeline.IMMEDIATE,
        attack=AttackVector.CLASSICAL_PLUS_GROVER,
        logical_qubits=640,
        physical_qubits_range="~1.3K noisy qubits",
        key_size=128,
        confidence="HIGH",
        rationale="MD5-based crypt ($1$): Only 1000 iterations. Classically weak, quantum-trivial.",
        recommendation="Migrate to yescrypt ($y$) or Argon2id",
        references=["NIST SP 800-63B"],
    )
    db["sha256crypt"] = _AlgoRecord(
        canonical="sha256crypt",
        family=CryptoFamily.KDF,
        risk=QuantumRisk.PARTIAL,
        timeline=RiskTimeline.LONG_TERM,
        attack=AttackVector.GROVERS_KEY_SEARCH,
        logical_qubits=2500,
        physical_qubits_range="~5K noisy qubits",
        key_size=256,
        confidence="MEDIUM",
        rationale="SHA-256 based crypt ($5$): Configurable rounds. Adequate if rounds >= 500,000.",
        recommendation="Consider migration to yescrypt or Argon2id",
        references=["NIST SP 800-63B"],
    )
    db["sha512crypt"] = _AlgoRecord(
        canonical="sha512crypt",
        family=CryptoFamily.KDF,
        risk=QuantumRisk.PARTIAL,
        timeline=RiskTimeline.LONG_TERM,
        attack=AttackVector.GROVERS_KEY_SEARCH,
        logical_qubits=4500,
        physical_qubits_range="~9K noisy qubits",
        key_size=512,
        confidence="MEDIUM",
        rationale="SHA-512 based crypt ($6$): Configurable rounds. Strong with high round count.",
        recommendation="Adequate with >= 500,000 rounds. Consider Argon2id for new systems.",
        references=["NIST SP 800-63B"],
    )
    db["yescrypt"] = _AlgoRecord(
        canonical="yescrypt",
        family=CryptoFamily.KDF,
        risk=QuantumRisk.SAFE,
        timeline=RiskTimeline.SAFE,
        attack=AttackVector.MEMORY_HARD_RESISTANT,
        logical_qubits=10000,
        physical_qubits_range="~20K+ noisy qubits",
        key_size=256,
        confidence="MEDIUM",
        rationale="yescrypt: Memory-hard, NIST-recommended for Linux shadow passwords.",
        recommendation="Quantum-resistant. Default on modern Linux systems.",
        references=["NIST SP 800-63B", "Linux-PAM documentation"],
    )
    # NTLM
    db["ntlm"] = _AlgoRecord(
        canonical="ntlm",
        family=CryptoFamily.SHA,
        risk=QuantumRisk.VULNERABLE,
        timeline=RiskTimeline.IMMEDIATE,
        attack=AttackVector.CLASSICAL_PLUS_GROVER,
        logical_qubits=640,
        physical_qubits_range="~1.3K noisy qubits",
        key_size=128,
        confidence="HIGH",
        rationale="NTLM: Unsalted MD4 hash. Classically trivial, quantum-trivial.",
        recommendation="Migrate to Kerberos AES + Credential Guard",
        references=["Microsoft Security Baseline"],
    )
    # LM Hash
    db["lm"] = _AlgoRecord(
        canonical="lm",
        family=CryptoFamily.SHA,
        risk=QuantumRisk.VULNERABLE,
        timeline=RiskTimeline.IMMEDIATE,
        attack=AttackVector.CLASSICAL_PLUS_GROVER,
        logical_qubits=300,
        physical_qubits_range="~600 noisy qubits",
        key_size=56,
        confidence="HIGH",
        rationale="LM Hash: DES-based, case-insensitive, split into 7-byte halves. Trivially broken.",
        recommendation="Disable LM hash storage via Group Policy immediately",
        references=["Microsoft KB299656"],
    )

    # ── Post-Quantum Algorithms (QUANTUM SAFE) ───────────────────────────
    pqc_entries = [
        (
            "ml-kem",
            "ML-KEM (CRYSTALS-Kyber): NIST-standardized lattice-based KEM.",
            "NIST FIPS 203",
        ),
        ("ml-kem-512", "ML-KEM-512: 128-bit post-quantum security.", "NIST FIPS 203"),
        ("ml-kem-768", "ML-KEM-768: 192-bit post-quantum security.", "NIST FIPS 203"),
        ("ml-kem-1024", "ML-KEM-1024: 256-bit post-quantum security.", "NIST FIPS 203"),
        (
            "ml-dsa",
            "ML-DSA (CRYSTALS-Dilithium): NIST-standardized lattice-based signature.",
            "NIST FIPS 204",
        ),
        ("ml-dsa-44", "ML-DSA-44: 128-bit post-quantum security.", "NIST FIPS 204"),
        ("ml-dsa-65", "ML-DSA-65: 192-bit post-quantum security.", "NIST FIPS 204"),
        ("ml-dsa-87", "ML-DSA-87: 256-bit post-quantum security.", "NIST FIPS 204"),
        (
            "slh-dsa",
            "SLH-DSA (SPHINCS+): NIST-standardized hash-based stateless signature.",
            "NIST FIPS 205",
        ),
    ]
    for name, rat, ref in pqc_entries:
        db[name] = _AlgoRecord(
            canonical=name,
            family=CryptoFamily.PQC,
            risk=QuantumRisk.SAFE,
            timeline=RiskTimeline.SAFE,
            attack=AttackVector.NONE_KNOWN,
            logical_qubits=0,
            physical_qubits_range="N/A — quantum-safe by design",
            key_size=0,
            confidence="HIGH",
            rationale=rat,
            recommendation=f"Quantum-safe. NIST standardized ({ref}).",
            references=[ref, "NIST IR 8547"],
        )

    return db


# ── Alias Registry ───────────────────────────────────────────────────────────

_ALIASES: dict[str, str] = {
    # RSA aliases
    "rsa": "rsa-2048",
    "rsa2048": "rsa-2048",
    "rsa4096": "rsa-4096",
    "rsa1024": "rsa-1024",
    "rsa3072": "rsa-3072",
    "rsa8192": "rsa-8192",
    # ECC aliases
    "ecdsa": "ecdsa-p256",
    "p256": "ecdsa-p256",
    "p-256": "ecdsa-p256",
    "secp256r1": "ecdsa-p256",
    "prime256v1": "ecdsa-p256",
    "p384": "ecdsa-p384",
    "p-384": "ecdsa-p384",
    "secp384r1": "ecdsa-p384",
    "p521": "ecdsa-p521",
    "p-521": "ecdsa-p521",
    "secp521r1": "ecdsa-p521",
    "curve25519": "ed25519",
    "edwards25519": "ed25519",
    "ecdh": "ecdh-p256",
    # DH aliases
    "diffie-hellman": "dh-2048",
    "dsa": "dsa-1024",
    # Hash aliases
    "sha-1": "sha1",
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
    "sha-3": "sha3-256",
    "sha-3-256": "sha3-256",
    "sha-3-512": "sha3-512",
    "sha2": "sha256",
    "sha2-256": "sha256",
    "blake2": "blake2b",
    # KDF aliases
    "argon2i": "argon2",
    "argon2d": "argon2",
    "bcrypt-sha256": "bcrypt",
    # PQC aliases
    "kyber": "ml-kem",
    "kyber512": "ml-kem-512",
    "kyber768": "ml-kem-768",
    "kyber1024": "ml-kem-1024",
    "dilithium": "ml-dsa",
    "dilithium2": "ml-dsa-44",
    "dilithium3": "ml-dsa-65",
    "dilithium5": "ml-dsa-87",
    "sphincs": "slh-dsa",
    "sphincs+": "slh-dsa",
    # Windows
    "net-ntlmv1": "ntlm",
    "net-ntlmv2": "ntlm",
    "lm-hash": "lm",
    "lanman": "lm",
}


# ── Algorithm Parsing Engine ─────────────────────────────────────────────────


def _normalize_algorithm(raw: str) -> str:
    """Normalize an algorithm name to its canonical form.

    Handles case, whitespace, common separators, and known aliases.
    """
    key = raw.strip().lower().replace(" ", "-").replace("_", "-")

    # Direct alias match
    if key in _ALIASES:
        return _ALIASES[key]

    return key


def _infer_from_pattern(raw: str) -> ScanResult | None:
    """Try to infer algorithm from patterns when not in the database.

    Handles things like 'rsa-7680', 'ecdsa-secp256k1', etc.
    """
    key = raw.strip().lower().replace(" ", "-").replace("_", "-")

    # RSA with arbitrary bit size
    m = re.match(r"^rsa[- ]?(\d+)$", key)
    if m:
        bits = int(m.group(1))
        if bits < 1536:
            tl = RiskTimeline.IMMEDIATE
        elif bits <= 2048:
            tl = RiskTimeline.NEAR_TERM
        elif bits <= 4096:
            tl = RiskTimeline.MEDIUM_TERM
        else:
            tl = RiskTimeline.MEDIUM_TERM
        logical_q = bits * 2  # Rough: 2n qubits for n-bit factoring
        return ScanResult(
            asset_type="algorithm",
            algorithm=raw,
            normalized_algorithm=f"rsa-{bits}",
            family=CryptoFamily.RSA,
            key_size=bits,
            risk=QuantumRisk.VULNERABLE,
            timeline=tl,
            attack_vector=AttackVector.SHORS_FACTORING,
            logical_qubits_estimate=logical_q,
            physical_qubits_estimate=f"~{logical_q * 5_000 // 2048}M noisy qubits (extrapolated)",
            confidence="MEDIUM",
            rationale=f"RSA-{bits} is vulnerable to Shor's integer factorization algorithm.",
            recommendation="Migrate to ML-KEM (FIPS 203)",
            references_basis=["Gidney & Ekerå (2021)", "NIST IR 8547"],
            assumptions=["Qubit estimate extrapolated from known RSA-2048 resource estimates"],
        )

    # ECDSA with named curve
    m = re.match(r"^ecdsa[- ]?(secp\d+\w+|p-?\d+|brainpool\w+)$", key)
    if m:
        curve = m.group(1)
        bits_m = re.search(r"(\d+)", curve)
        bits = int(bits_m.group(1)) if bits_m else 256
        return ScanResult(
            asset_type="algorithm",
            algorithm=raw,
            normalized_algorithm=f"ecdsa-{curve}",
            family=CryptoFamily.ECC,
            key_size=bits,
            risk=QuantumRisk.VULNERABLE,
            timeline=RiskTimeline.NEAR_TERM if bits <= 256 else RiskTimeline.MEDIUM_TERM,
            attack_vector=AttackVector.SHORS_ECDLP,
            logical_qubits_estimate=int(bits * 9.1),  # ~9n qubits for n-bit ECDLP
            physical_qubits_estimate=f"~{int(bits * 9.1 * 2000)}K noisy qubits (extrapolated)",
            confidence="MEDIUM",
            rationale=f"ECDSA on {curve} is vulnerable to Shor's ECDLP algorithm.",
            recommendation="Migrate to ML-DSA (FIPS 204)",
            references_basis=["Roetteler et al. (2017)", "NIST IR 8547"],
        )

    return None


# ══════════════════════════════════════════════════════════════════════════════
# PQCScanner — Main Scanner Class
# ══════════════════════════════════════════════════════════════════════════════


class PQCScanner:
    """Post-Quantum Cryptography vulnerability scanner.

    Production-grade scanner that classifies cryptographic assets by their
    vulnerability to quantum attacks. Supports SSH keys, hash strings,
    X.509 certificates, and algorithm names.

    All outputs are classifier results — they are literature-backed
    risk assessments, not measured hardware benchmarks.

    Usage:
        scanner = PQCScanner()

        # Scan an algorithm name
        result = scanner.scan_algorithm("rsa-2048")

        # Scan an SSH key file
        result = scanner.scan_ssh_key("/path/to/id_rsa")

        # Scan a hash string
        result = scanner.scan_hash("$6$salt$hash...")

        # Scan an X.509 certificate
        result = scanner.scan_x509_cert("/path/to/cert.pem")

        # Generate aggregate report
        report = scanner.full_report([result1, result2, result3])
    """

    def __init__(self) -> None:
        self._db = _build_algo_db()

    def scan_algorithm(self, algo: str) -> ScanResult:
        """Scan a named algorithm for quantum vulnerability.

        Performs robust parsing, alias resolution, and pattern matching.
        Falls back to UNKNOWN with an explanation for unrecognized inputs.
        """
        if not algo or not algo.strip():
            return ScanResult(
                asset_type="algorithm",
                algorithm=algo or "",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
                rationale="Empty or whitespace-only algorithm name provided.",
                recommendation="Provide a valid algorithm identifier.",
            )

        normalized = _normalize_algorithm(algo)
        record = self._db.get(normalized)

        if record:
            return self._record_to_result(record, asset_type="algorithm", raw_algo=algo)

        # Try pattern inference for unsupported key sizes
        inferred = _infer_from_pattern(algo)
        if inferred:
            inferred.result_origin = "pattern_inference"
            inferred.assumptions.append(
                "Algorithm inferred from naming pattern, not exact database match"
            )
            return inferred

        # Unknown algorithm
        return ScanResult(
            asset_type="algorithm",
            algorithm=algo,
            normalized_algorithm=normalized,
            risk=QuantumRisk.UNKNOWN,
            confidence="LOW",
            rationale=f"Algorithm '{algo}' (normalized: '{normalized}') not in PQC knowledge base.",
            recommendation="Manual review required. Check NIST PQC transition guidance.",
            limitations=["Algorithm not recognized by automated scanner"],
        )

    def scan_ssh_key(self, key_path: str) -> ScanResult:
        """Scan an SSH key file for quantum vulnerability.

        Detects key type from PEM/OpenSSH headers and maps to quantum risk.
        """
        p = Path(key_path)
        if not p.exists():
            return ScanResult(
                asset_type="ssh_key",
                details=f"File not found: {key_path}",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
            )

        try:
            content = p.read_text(errors="replace")
        except Exception as e:
            return ScanResult(
                asset_type="ssh_key",
                details=f"Read error: {e}",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
            )

        # Detect key type from header
        algo = self._detect_ssh_key_type(content)

        result = self.scan_algorithm(algo)
        result.asset_type = "ssh_key"
        result.details = f"Source: {key_path}"
        return result

    def scan_hash(self, hash_string: str) -> ScanResult:
        """Scan a hash string and determine its quantum vulnerability.

        Identifies hash type from prefix/length and classifies quantum risk.
        """
        h = hash_string.strip()
        algo = self._detect_hash_type(h)

        result = self.scan_algorithm(algo)
        result.asset_type = "hash"
        result.details = f"Hash: {h[:32]}{'...' if len(h) > 32 else ''}"
        return result

    def scan_x509_cert(self, cert_path: str) -> ScanResult:
        """Scan an X.509 certificate for post-quantum vulnerability.

        Uses the ``cryptography`` package if available, otherwise falls back
        to PEM header parsing for basic detection.
        """
        p = Path(cert_path)
        if not p.exists():
            return ScanResult(
                asset_type="certificate",
                details=f"Certificate not found: {cert_path}",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
            )

        # Try cryptography package first
        try:
            return self._scan_x509_with_cryptography(p)
        except ImportError:
            logger.debug("cryptography package not available, using PEM fallback")
            return self._scan_x509_pem_fallback(p)
        except Exception as e:
            return ScanResult(
                asset_type="certificate",
                risk=QuantumRisk.UNKNOWN,
                details=f"Parse error: {e}",
                confidence="LOW",
            )

    def full_report(self, results: list[ScanResult]) -> dict:
        """Generate a comprehensive PQC vulnerability portfolio report."""
        if not results:
            return {"total_assets": 0}

        critical = [r for r in results if r.risk == QuantumRisk.VULNERABLE]
        partial = [r for r in results if r.risk == QuantumRisk.PARTIAL]
        safe = [r for r in results if r.risk == QuantumRisk.SAFE]
        unknown = [r for r in results if r.risk == QuantumRisk.UNKNOWN]

        avg_risk = sum(r.risk_score for r in results) / len(results)

        return {
            "mode": "CLASSIFIER",
            "measured": False,
            "implementation_status": "PRODUCTION",
            "total_assets": len(results),
            "quantum_vulnerable": len(critical),
            "quantum_partial": len(partial),
            "quantum_safe": len(safe),
            "quantum_unknown": len(unknown),
            "avg_risk_score": round(avg_risk, 1),
            "highest_risk": (
                max(results, key=lambda r: r.risk_score).algorithm if results else "N/A"
            ),
            "immediate_actions": [
                {
                    "algorithm": r.algorithm,
                    "risk": r.risk.value,
                    "attack_vector": r.attack_vector.value,
                    "recommendation": r.recommendation,
                }
                for r in critical
            ],
            "migration_timeline": {
                "immediate": [r.algorithm for r in results if r.timeline == RiskTimeline.IMMEDIATE],
                "near_term": [r.algorithm for r in results if r.timeline == RiskTimeline.NEAR_TERM],
                "medium_term": [
                    r.algorithm for r in results if r.timeline == RiskTimeline.MEDIUM_TERM
                ],
                "long_term_or_safe": [
                    r.algorithm
                    for r in results
                    if r.timeline in (RiskTimeline.LONG_TERM, RiskTimeline.SAFE)
                ],
            },
        }

    # ── Internal helpers ──────────────────────────────────────────────────

    def _record_to_result(
        self, rec: _AlgoRecord, asset_type: str = "algorithm", raw_algo: str = ""
    ) -> ScanResult:
        """Convert an internal _AlgoRecord to a public ScanResult."""
        return ScanResult(
            asset_type=asset_type,
            algorithm=raw_algo or rec.canonical,
            normalized_algorithm=rec.canonical,
            family=rec.family,
            key_size=rec.key_size,
            risk=rec.risk,
            attack_vector=rec.attack,
            timeline=rec.timeline,
            logical_qubits_estimate=rec.logical_qubits,
            physical_qubits_estimate=rec.physical_qubits_range,
            confidence=rec.confidence,
            rationale=rec.rationale,
            recommendation=rec.recommendation,
            references_basis=list(rec.references),
            assumptions=list(rec.assumptions),
            limitations=list(rec.limitations),
        )

    def _detect_ssh_key_type(self, content: str) -> str:
        """Detect SSH key algorithm from file content."""
        if "BEGIN RSA PRIVATE KEY" in content or "BEGIN RSA" in content:
            return f"rsa-{self._estimate_rsa_size(content)}"
        if "BEGIN EC PRIVATE KEY" in content:
            if "prime256v1" in content or "P-256" in content:
                return "ecdsa-p256"
            if "secp384r1" in content or "P-384" in content:
                return "ecdsa-p384"
            if "secp521r1" in content or "P-521" in content:
                return "ecdsa-p521"
            return "ecdsa-p256"  # Default ECC assumption
        if "BEGIN OPENSSH PRIVATE KEY" in content:
            lower = content.lower()
            if "ed25519" in lower:
                return "ed25519"
            if "ed448" in lower:
                return "ed448"
            if "ecdsa" in lower:
                return "ecdsa-p256"
            return "rsa-2048"  # Default OpenSSH
        if "BEGIN DSA PRIVATE KEY" in content:
            return "dsa-1024"
        return "unknown"

    def _estimate_rsa_size(self, content: str) -> int:
        """Heuristic RSA key size estimation from PEM content length."""
        lines = [
            ln
            for ln in content.split("\n")
            if ln
            and not ln.startswith("-----")
            and not ln.startswith("Proc")
            and not ln.startswith("DEK-Info")
        ]
        total_b64 = sum(len(ln.strip()) for ln in lines)
        byte_count = total_b64 * 3 // 4

        if byte_count < 700:
            return 1024
        elif byte_count < 1700:
            return 2048
        elif byte_count < 2500:
            return 3072
        elif byte_count < 3400:
            return 4096
        else:
            return 8192

    def _detect_hash_type(self, h: str) -> str:
        """Detect hash algorithm from hash string format."""
        # Unix crypt formats
        if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
            return "bcrypt"
        if h.startswith("$argon2"):
            return "argon2id" if "argon2id" in h else "argon2"
        if h.startswith("$6$"):
            return "sha512crypt"
        if h.startswith("$5$"):
            return "sha256crypt"
        if h.startswith("$1$"):
            return "md5crypt"
        if h.startswith("$y$") or h.startswith("$7$"):
            return "yescrypt"
        if h.startswith("$scrypt$"):
            return "scrypt"

        # Raw hex hashes
        hex_lower = h.lower()
        if all(c in "0123456789abcdef" for c in hex_lower):
            hex_len = len(hex_lower)
            hash_sizes = {
                32: "md5",
                40: "sha1",
                56: "sha224",
                64: "sha256",
                96: "sha384",
                128: "sha512",
            }
            if hex_len in hash_sizes:
                return hash_sizes[hex_len]

        # NTLM (32 hex, often uppercase)
        if len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h):
            return "md5"  # or NTLM — ambiguous without context

        return "unknown"

    def _scan_x509_with_cryptography(self, path: Path) -> ScanResult:
        """Scan X.509 cert using the ``cryptography`` package."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed448,
            ed25519,
            rsa,
        )

        raw = path.read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(raw)
        except Exception:
            cert = x509.load_der_x509_certificate(raw)

        pub = cert.public_key()

        if isinstance(pub, rsa.RSAPublicKey):
            algo = f"rsa-{pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            curve = pub.curve.name.lower()
            if "256" in curve:
                algo = "ecdsa-p256"
            elif "384" in curve:
                algo = "ecdsa-p384"
            elif "521" in curve:
                algo = "ecdsa-p521"
            else:
                algo = f"ecdsa-{curve}"
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            algo = "ed25519"
        elif isinstance(pub, ed448.Ed448PublicKey):
            algo = "ed448"
        elif isinstance(pub, dsa.DSAPublicKey):
            algo = f"dsa-{pub.key_size}"
        else:
            algo = "unknown"

        subject = cert.subject.rfc4514_string()
        sig_oid = cert.signature_algorithm_oid.dotted_string

        result = self.scan_algorithm(algo)
        result.asset_type = "certificate"
        result.details = f"Subject: {subject} | Sig OID: {sig_oid} | Source: {path}"
        return result

    def _scan_x509_pem_fallback(self, path: Path) -> ScanResult:
        """Fallback X.509 scan using PEM header parsing (no cryptography pkg)."""
        try:
            content = path.read_text(errors="replace")
        except Exception as e:
            return ScanResult(
                asset_type="certificate",
                details=f"Read error: {e}",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
            )

        # Very basic header detection
        if "BEGIN CERTIFICATE" not in content:
            return ScanResult(
                asset_type="certificate",
                details="File does not appear to be a PEM certificate",
                risk=QuantumRisk.UNKNOWN,
                confidence="LOW",
            )

        # Check for algorithm hints in the PEM metadata
        lower = content.lower()
        if "rsa" in lower:
            algo = "rsa-2048"  # Default RSA assumption from PEM
        elif "ecdsa" in lower or "ec" in lower:
            algo = "ecdsa-p256"
        elif "ed25519" in lower:
            algo = "ed25519"
        elif "dsa" in lower:
            algo = "dsa-1024"
        else:
            algo = "rsa-2048"  # Safe default assumption

        result = self.scan_algorithm(algo)
        result.asset_type = "certificate"
        result.details = (
            f"Source: {path} (PEM header fallback — install 'cryptography' for full parsing)"
        )
        result.confidence = "LOW"
        result.assumptions.append(
            "Algorithm inferred from PEM text content, not cryptographic parsing"
        )
        return result
