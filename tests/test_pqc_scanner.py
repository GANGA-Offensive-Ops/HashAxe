# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_pqc_scanner.py
#  Comprehensive pytest suite for the PQC Scanner module.
#  Validates parsing, classification, qubit estimation, provenance, and edge cases.
#
# ⚠️ Version 2.0.0 — Production Audit Tests 💀
# ==========================================================================================
"""
tests/test_pqc_scanner.py — Full test suite for hashaxe.pqc.scanner.

Tests cover:
  - Algorithm parsing and normalization
  - Crypto family inference
  - Qubit estimation correctness
  - Risk classification accuracy
  - Attack vector mapping
  - SSH key scanning
  - Hash string detection
  - Unknown/edge-case handling
  - Provenance field correctness
  - Full report generation
  - Backward compatibility
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest


class TestAlgorithmParsing:
    """Test robust algorithm name parsing and normalization."""

    def test_direct_name(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.normalized_algorithm == "rsa-2048"

    def test_alias_rsa(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa")
        assert result.normalized_algorithm == "rsa-2048"

    def test_alias_kyber(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("kyber")
        assert result.normalized_algorithm == "ml-kem"
        assert result.risk == QuantumRisk.SAFE

    def test_alias_dilithium(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("dilithium")
        assert result.normalized_algorithm == "ml-dsa"
        assert result.risk == QuantumRisk.SAFE

    def test_alias_sphincs(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("sphincs+")
        assert result.normalized_algorithm == "slh-dsa"
        assert result.risk == QuantumRisk.SAFE

    def test_case_insensitive(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        r1 = scanner.scan_algorithm("RSA-2048")
        r2 = scanner.scan_algorithm("rsa-2048")
        assert r1.normalized_algorithm == r2.normalized_algorithm

    def test_whitespace_handling(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("  rsa-2048  ")
        assert result.normalized_algorithm == "rsa-2048"

    def test_underscore_to_dash(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa_2048")
        assert result.normalized_algorithm == "rsa-2048"

    def test_empty_string(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("")
        assert result.risk == QuantumRisk.UNKNOWN

    def test_unknown_algorithm(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("super_custom_algo_v99")
        assert result.risk == QuantumRisk.UNKNOWN
        assert result.confidence == "LOW"

    def test_ecc_curve_aliases(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        for alias in ["secp256r1", "prime256v1", "p256", "p-256"]:
            result = scanner.scan_algorithm(alias)
            assert result.family == CryptoFamily.ECC
            assert result.normalized_algorithm == "ecdsa-p256"


class TestCryptoFamilyInference:
    """Test crypto family classification."""

    def test_rsa_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("rsa-4096").family == CryptoFamily.RSA

    def test_ecc_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("ed25519").family == CryptoFamily.ECC
        assert scanner.scan_algorithm("ecdsa-p384").family == CryptoFamily.ECC

    def test_dh_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("dh-2048").family == CryptoFamily.DH

    def test_aes_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("aes-256").family == CryptoFamily.AES

    def test_hash_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("sha256").family == CryptoFamily.SHA

    def test_kdf_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("bcrypt").family == CryptoFamily.KDF
        assert scanner.scan_algorithm("argon2id").family == CryptoFamily.KDF
        assert scanner.scan_algorithm("scrypt").family == CryptoFamily.KDF

    def test_pqc_family(self):
        from hashaxe.pqc.scanner import PQCScanner, CryptoFamily
        scanner = PQCScanner()
        assert scanner.scan_algorithm("ml-kem").family == CryptoFamily.PQC
        assert scanner.scan_algorithm("ml-dsa").family == CryptoFamily.PQC
        assert scanner.scan_algorithm("slh-dsa").family == CryptoFamily.PQC


class TestRiskClassification:
    """Test quantum risk assessment accuracy."""

    def test_rsa_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        for size in [1024, 2048, 4096]:
            result = scanner.scan_algorithm(f"rsa-{size}")
            assert result.risk == QuantumRisk.VULNERABLE

    def test_ecc_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        for algo in ["ed25519", "ecdsa-p256", "ecdsa-p384"]:
            result = scanner.scan_algorithm(algo)
            assert result.risk == QuantumRisk.VULNERABLE

    def test_aes256_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("aes-256").risk == QuantumRisk.SAFE

    def test_aes128_partial(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("aes-128").risk == QuantumRisk.PARTIAL

    def test_sha256_partial(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("sha256").risk == QuantumRisk.PARTIAL

    def test_md5_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("md5").risk == QuantumRisk.VULNERABLE

    def test_sha1_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("sha1").risk == QuantumRisk.VULNERABLE

    def test_argon2_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("argon2").risk == QuantumRisk.SAFE
        assert scanner.scan_algorithm("argon2id").risk == QuantumRisk.SAFE

    def test_pqc_algorithms_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        for algo in ["ml-kem", "ml-kem-768", "ml-dsa", "ml-dsa-65", "slh-dsa"]:
            assert scanner.scan_algorithm(algo).risk == QuantumRisk.SAFE

    def test_ntlm_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("ntlm").risk == QuantumRisk.VULNERABLE

    def test_descrypt_vulnerable(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("descrypt").risk == QuantumRisk.VULNERABLE

    def test_yescrypt_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        assert scanner.scan_algorithm("yescrypt").risk == QuantumRisk.SAFE


class TestAttackVectors:
    """Test correct attack vector classification."""

    def test_rsa_shors_factoring(self):
        from hashaxe.pqc.scanner import PQCScanner, AttackVector
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.attack_vector == AttackVector.SHORS_FACTORING

    def test_ecc_shors_ecdlp(self):
        from hashaxe.pqc.scanner import PQCScanner, AttackVector
        scanner = PQCScanner()
        result = scanner.scan_algorithm("ed25519")
        assert result.attack_vector == AttackVector.SHORS_ECDLP

    def test_aes_grovers_key_search(self):
        from hashaxe.pqc.scanner import PQCScanner, AttackVector
        scanner = PQCScanner()
        result = scanner.scan_algorithm("aes-256")
        assert result.attack_vector == AttackVector.GROVERS_KEY_SEARCH

    def test_sha_grovers_preimage(self):
        from hashaxe.pqc.scanner import PQCScanner, AttackVector
        scanner = PQCScanner()
        result = scanner.scan_algorithm("sha256")
        assert result.attack_vector == AttackVector.GROVERS_PREIMAGE

    def test_pqc_none_known(self):
        from hashaxe.pqc.scanner import PQCScanner, AttackVector
        scanner = PQCScanner()
        result = scanner.scan_algorithm("ml-kem")
        assert result.attack_vector == AttackVector.NONE_KNOWN


class TestQubitEstimates:
    """Test qubit estimation values."""

    def test_rsa2048_logical_qubits(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.logical_qubits_estimate == 4096

    def test_ed25519_logical_qubits(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("ed25519")
        assert result.logical_qubits_estimate == 1700

    def test_pqc_zero_qubits(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("ml-kem")
        assert result.logical_qubits_estimate == 0

    def test_physical_qubits_populated(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert "noisy qubits" in result.physical_qubits_estimate

    def test_backward_compat_qubits_needed(self):
        """Test that the old .qubits_needed property still works."""
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.qubits_needed == result.logical_qubits_estimate


class TestPatternInference:
    """Test inference for algorithms not in the database."""

    def test_rsa_7680(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk, CryptoFamily
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-7680")
        assert result.risk == QuantumRisk.VULNERABLE
        assert result.family == CryptoFamily.RSA
        assert result.logical_qubits_estimate > 0
        assert "extrapolated" in result.physical_qubits_estimate.lower()


class TestProvenanceFields:
    """Test that every result has correct provenance metadata."""

    def test_mode_is_classifier(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.mode == "CLASSIFIER"

    def test_measured_is_false(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.measured is False

    def test_simulation_is_false(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.simulation is False

    def test_implementation_status(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.implementation_status == "PRODUCTION"

    def test_references_populated(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert len(result.references_basis) > 0

    def test_rationale_populated(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert len(result.rationale) > 0

    def test_recommendation_populated(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert "ML-KEM" in result.recommendation


class TestRiskScore:
    """Test numeric risk score computation."""

    def test_rsa1024_highest(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-1024")
        assert result.risk_score == 90  # VULNERABLE * IMMEDIATE = 90 * 1.0

    def test_aes256_zero(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_algorithm("aes-256")
        assert result.risk_score == 0

    def test_ordering(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        r_rsa1024 = scanner.scan_algorithm("rsa-1024")
        r_rsa2048 = scanner.scan_algorithm("rsa-2048")
        r_aes256 = scanner.scan_algorithm("aes-256")
        assert r_rsa1024.risk_score >= r_rsa2048.risk_score
        assert r_rsa2048.risk_score > r_aes256.risk_score


class TestHashScanning:
    """Test hash string format detection."""

    def test_md5_hex(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("5d41402abc4b2a76b9719d911017c592")
        assert result.asset_type == "hash"
        assert "md5" in result.normalized_algorithm

    def test_sha1_hex(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert "sha1" in result.normalized_algorithm

    def test_sha256_hex(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert "sha256" in result.normalized_algorithm

    def test_bcrypt_format(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("$2b$12$LJ3m4ys3Lg.XTn6fY/Y1d.somehashcontenthere12")
        assert "bcrypt" in result.normalized_algorithm

    def test_sha512crypt(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("$6$salt$hashstringhere")
        assert "sha512crypt" in result.normalized_algorithm

    def test_md5crypt(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("$1$salt$hashhere")
        assert "md5crypt" in result.normalized_algorithm

    def test_argon2_format(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_hash("$argon2id$v=19$m=65536$t=3$somehash")
        assert "argon2" in result.normalized_algorithm


class TestSSHKeyScanning:
    """Test SSH key file scanning."""

    def test_ssh_key_file_not_found(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_ssh_key("/nonexistent/key")
        assert result.risk == QuantumRisk.UNKNOWN
        assert "not found" in result.details.lower()

    def test_scan_real_test_key(self):
        """Scan the actual test RSA key in the repo."""
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        key_path = os.path.join(os.path.dirname(__file__), "..", "test_files", "test_id_rsa")
        if not os.path.exists(key_path):
            pytest.skip("test_id_rsa not found")
        scanner = PQCScanner()
        result = scanner.scan_ssh_key(key_path)
        assert result.asset_type == "ssh_key"
        assert result.risk in (QuantumRisk.VULNERABLE, QuantumRisk.UNKNOWN)


class TestFullReport:
    """Test aggregate portfolio reporting."""

    def test_report_structure(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        results = [
            scanner.scan_algorithm("rsa-2048"),
            scanner.scan_algorithm("aes-256"),
            scanner.scan_algorithm("ed25519"),
        ]
        report = scanner.full_report(results)
        assert report["total_assets"] == 3
        assert report["quantum_vulnerable"] >= 2
        assert report["mode"] == "CLASSIFIER"
        assert report["measured"] is False

    def test_report_migration_timeline(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        results = [
            scanner.scan_algorithm("rsa-1024"),
            scanner.scan_algorithm("rsa-2048"),
            scanner.scan_algorithm("aes-256"),
        ]
        report = scanner.full_report(results)
        assert "migration_timeline" in report
        assert len(report["migration_timeline"]["immediate"]) >= 1

    def test_empty_report(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        report = scanner.full_report([])
        assert report["total_assets"] == 0
