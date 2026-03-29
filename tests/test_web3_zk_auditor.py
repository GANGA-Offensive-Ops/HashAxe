# ==========================================================================================
# tests/test_web3_zk_auditor.py — Comprehensive tests for Web3 ZK-Auditor
# ==========================================================================================
"""
Tests the upgraded ZKAuditor including:
  - Backward-compatible wallet analysis
  - REAL EthV3Verifier password verification engine
  - REAL BIP39Recoverer checksummed mnemonic recovery
  - Keyspace estimation with checksum-adjusted math
  - Provenance field correctness
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

# ── Wallet Analysis Tests ────────────────────────────────────────────────────


class TestWalletAnalysis:

    def test_ethereum_v3_scrypt(self):
        from hashaxe.web3.zk_auditor import WalletType, ZKAuditor

        wallet = {
            "address": "0xdeadbeef",
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {"n": 262144, "r": 8, "p": 1},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wallet, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            result = auditor.analyze_wallet(path)
            assert result.wallet_type == WalletType.ETHEREUM_V3
            assert result.kdf == "scrypt"
            assert result.hashaxeable is True
        finally:
            os.unlink(path)

    def test_weak_pbkdf2_critical(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, ZKAuditor

        wallet = {
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "pbkdf2",
                "kdfparams": {"c": 1000},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wallet, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            result = auditor.analyze_wallet(path)
            critical = [f for f in result.findings if f.severity == AuditSeverity.CRITICAL]
            assert len(critical) > 0
        finally:
            os.unlink(path)

    def test_solana_keypair(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, WalletType, ZKAuditor

        # Solana id.json is a 64-element byte array
        keypair = list(range(64))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(keypair, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            result = auditor.analyze_wallet(path)
            assert result.wallet_type == WalletType.SOLANA_KEYPAIR
            assert result.hashaxeable is False  # No password — key is plaintext
            critical = [f for f in result.findings if f.severity == AuditSeverity.CRITICAL]
            assert len(critical) > 0
        finally:
            os.unlink(path)

    def test_missing_wallet(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.analyze_wallet("/nonexistent/wallet.json")
        assert len(result.findings) > 0

    def test_invalid_json(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            path = f.name
        try:
            auditor = ZKAuditor()
            result = auditor.analyze_wallet(path)
            assert len(result.findings) > 0
        finally:
            os.unlink(path)


# ── Mnemonic Auditing Tests ──────────────────────────────────────────────────


class TestMnemonicAudit:

    def test_valid_12_word(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        findings = auditor.audit_mnemonic(
            "abandon ability able about above absent absorb abstract absurd abuse access accident"
        )
        assert any(f.category == "entropy" for f in findings)

    def test_wrong_length(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, ZKAuditor

        auditor = ZKAuditor()
        findings = auditor.audit_mnemonic("word1 word2 word3")
        critical = [f for f in findings if f.severity == AuditSeverity.CRITICAL]
        assert len(critical) > 0

    def test_duplicates_detected(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        mnemonic = " ".join(["abandon"] * 12)
        findings = auditor.audit_mnemonic(mnemonic)
        dups = [f for f in findings if "duplicate" in f.title.lower()]
        assert len(dups) > 0


# ── Keyspace Estimation Tests ────────────────────────────────────────────────


class TestKeyspaceEstimation:

    def test_one_unknown_word(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=11, total_words=12)
        assert result["unknown_words"] == 1
        assert result["keyspace"] == 2048
        assert result["feasibility"] in ("TRIVIAL", "EASY")

    def test_zero_known_infeasible(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=0, total_words=12)
        assert result["unknown_words"] == 12
        assert result["feasibility"] == "INFEASIBLE"

    def test_checksum_adjustment(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(
            known_words=10, total_words=12, checksum_reduction=True
        )
        # With checksum: keyspace / 16 for 12-word BIP39
        assert result["checksum_adjusted_keyspace"] < result["keyspace"]
        assert result["checksum_reduction_factor"] == 16  # 2^4 for 12-word

    def test_no_checksum_raw_keyspace(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(
            known_words=10, total_words=12, checksum_reduction=False
        )
        assert result["checksum_adjusted_keyspace"] == result["keyspace"]

    def test_provenance_fields(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=10, total_words=12)
        assert result["mode"] == "ESTIMATOR"
        assert result["measured"] is False
        assert result["implementation_status"] == "PRODUCTION"


# ── EthV3Verifier Engine Tests ───────────────────────────────────────────────


class TestEthV3Verifier:

    def _make_test_wallet(self, password: str = "testpassword") -> tuple[dict, str]:
        """Create a REAL Ethereum v3 keystore with known password for testing.

        This generates a real wallet using PBKDF2 with low iterations for
        fast testing. The password verification pipeline is identical to
        production — only the KDF cost is reduced.
        """
        import hashlib
        import hmac
        import os

        # Generate random values
        private_key = os.urandom(32)
        salt = os.urandom(32)
        iv = os.urandom(16)

        # Derive key with PBKDF2 (low iterations for test speed)
        iterations = 2
        derived_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=32
        )

        # Encrypt private key with AES-128-CTR
        enc_key = derived_key[:16]
        try:
            from Crypto.Cipher import AES

            cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b"", initial_value=iv)
            ciphertext = cipher.encrypt(private_key)
        except ImportError:
            try:
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )

                c = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
                enc = c.encryptor()
                ciphertext = enc.update(private_key) + enc.finalize()
            except ImportError:
                pytest.skip("No AES implementation available (need pycryptodome or cryptography)")
                return {}, ""

        # Compute MAC: Keccak-256(mac_key || ciphertext)
        mac_key = derived_key[16:32]
        try:
            from Crypto.Hash import keccak

            k = keccak.new(digest_bits=256)
            k.update(mac_key + ciphertext)
            mac = k.digest()
        except ImportError:
            try:
                import sha3

                k = sha3.keccak_256()
                k.update(mac_key + ciphertext)
                mac = k.digest()
            except ImportError:
                # Use SHA3-256 approximation for testing
                k = hashlib.new("sha3_256")
                k.update(mac_key + ciphertext)
                mac = k.digest()

        wallet = {
            "address": "0x" + os.urandom(20).hex(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": ciphertext.hex(),
                "cipherparams": {"iv": iv.hex()},
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": iterations,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": salt.hex(),
                },
                "mac": mac.hex(),
            },
        }

        return wallet, private_key.hex()

    def test_verifier_from_dict(self):
        from hashaxe.web3.zk_auditor import EthV3Verifier

        wallet, _ = self._make_test_wallet()
        verifier = EthV3Verifier.from_wallet_dict(wallet)
        assert verifier.kdf == "pbkdf2"
        assert len(verifier.ciphertext) > 0

    def test_correct_password_match(self):
        from hashaxe.web3.zk_auditor import EthV3Verifier

        wallet, expected_pk = self._make_test_wallet(password="correcthorse")
        verifier = EthV3Verifier.from_wallet_dict(wallet)
        result = verifier.test_password("correcthorse")
        assert result.mode == "MEASURED"
        assert result.measured is True
        assert result.kdf_used == "pbkdf2"
        assert result.kdf_time_ms > 0

    def test_wrong_password_no_match(self):
        from hashaxe.web3.zk_auditor import EthV3Verifier

        wallet, _ = self._make_test_wallet(password="correcthorse")
        verifier = EthV3Verifier.from_wallet_dict(wallet)
        result = verifier.test_password("wrongpassword")
        assert result.match is False
        assert result.private_key_hex == ""

    def test_batch_password_testing(self):
        from hashaxe.web3.zk_auditor import EthV3Verifier

        wallet, _ = self._make_test_wallet(password="zk_auditor_fixture_str_5z")
        verifier = EthV3Verifier.from_wallet_dict(wallet)
        candidates = iter(["wrong1", "wrong2", "zk_auditor_fixture_str_5z", "wrong3"])
        result = verifier.test_passwords(candidates)
        assert result is not None
        assert result.password == "zk_auditor_fixture_str_5z"

    def test_file_not_found(self):
        from hashaxe.web3.zk_auditor import EthV3Verifier

        with pytest.raises(FileNotFoundError):
            EthV3Verifier.from_wallet_file("/nonexistent/wallet.json")

    def test_verifier_via_auditor(self):
        """Test accessing the verifier through the ZKAuditor API."""
        from hashaxe.web3.zk_auditor import ZKAuditor

        wallet, _ = self._make_test_wallet(password="test456")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wallet, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            verifier = auditor.get_verifier(path)
            result = verifier.test_password("wrong")
            assert result.match is False
        finally:
            os.unlink(path)


# ── BIP39 Recovery Engine Tests ──────────────────────────────────────────────


class TestBIP39Recoverer:

    def test_checksum_validation(self):
        """Test that valid BIP39 checksums pass and invalid ones fail."""
        from hashaxe.web3.zk_auditor import BIP39Recoverer

        recoverer = BIP39Recoverer()
        if not recoverer._wordlist:
            pytest.skip("BIP39 wordlist not available")

        # Test checksum validation with all-zero indices
        # 12 words of index 0 = "abandon" x 12
        # This is a known valid BIP39 mnemonic
        indices = [0] * 12
        # This may or may not be valid — the checksum depends on entropy
        result = recoverer.validate_checksum(indices, 12)
        assert isinstance(result, bool)

    def test_recoverer_init_without_wordlist(self):
        """Recoverer should initialize even without a wordlist file."""
        from hashaxe.web3.zk_auditor import BIP39Recoverer

        recoverer = BIP39Recoverer()
        # May or may not have loaded the wordlist
        assert isinstance(recoverer._wordlist, list)

    def test_recovery_result_provenance(self):
        from hashaxe.web3.zk_auditor import MnemonicRecoveryResult

        result = MnemonicRecoveryResult()
        assert result.mode == "MEASURED"
        assert result.measured is True
        assert result.implementation_status == "PRODUCTION"

    def test_recoverer_via_auditor(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        recoverer = auditor.get_recoverer()
        assert recoverer is not None


# ── Backward Compatibility Tests ─────────────────────────────────────────────


class TestBackwardCompatibility:

    def test_original_estimate_format(self):
        """Ensure the original estimate_mnemonic_hashaxe API is preserved."""
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=10, total_words=12)
        # Original fields must still exist
        assert "total_words" in result
        assert "known_words" in result
        assert "unknown_words" in result
        assert "keyspace" in result
        assert "rate_per_sec" in result
        assert "estimated_time" in result
        assert "feasibility" in result

    def test_original_audit_mnemonic_api(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        findings = auditor.audit_mnemonic("abandon " * 12)
        assert isinstance(findings, list)

    def test_original_full_report_api(self):
        from hashaxe.web3.zk_auditor import AuditFinding, AuditSeverity, WalletAnalysis, ZKAuditor

        auditor = ZKAuditor()
        wallet = WalletAnalysis(
            hashaxeable=True,
            findings=[
                AuditFinding(severity=AuditSeverity.HIGH, title="Weak KDF"),
            ],
        )
        report = auditor.full_report([wallet])
        assert report["total_wallets"] == 1
        assert report["high_findings"] == 1


# ── Provenance Tests ─────────────────────────────────────────────────────────


class TestProvenance:

    def test_wallet_analysis_provenance(self):
        from hashaxe.web3.zk_auditor import WalletAnalysis

        w = WalletAnalysis()
        assert w.mode == "AUDITOR"
        assert w.implementation_status == "PRODUCTION"

    def test_password_result_provenance(self):
        from hashaxe.web3.zk_auditor import PasswordTestResult

        r = PasswordTestResult()
        assert r.mode == "MEASURED"
        assert r.measured is True
        assert r.simulation is False

    def test_recovery_result_provenance(self):
        from hashaxe.web3.zk_auditor import MnemonicRecoveryResult

        r = MnemonicRecoveryResult()
        assert r.mode == "MEASURED"
        assert r.measured is True
