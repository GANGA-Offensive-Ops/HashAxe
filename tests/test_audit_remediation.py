"""
Tests for V4 Audit Remediation changes.

Validates:
  - AttackConfig new fields (rate limiting, checkpoint, AI tuning, smoothing)
  - AI generator rate limiting & seed determinism
  - Markov Add-k smoothing
  - PRINCE deduplication
  - PCFG keyboard-walk tokenization
  - Distributed master path traversal validation
  - PQC X.509 cert scanning (unit level)
  - Web3 Solana keypair detection
  - Auto-pwn hardware profiling
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── PATH SETUP ────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ===========================================================================
# 1. AttackConfig new fields
# ===========================================================================

class TestAttackConfigAuditFields(unittest.TestCase):
    """Validate new AttackConfig fields from audit remediation."""

    def test_default_values(self):
        from hashaxe.attacks import AttackConfig
        cfg = AttackConfig()
        self.assertEqual(cfg.max_candidates, 0)
        self.assertIsNone(cfg.checkpoint_file)
        self.assertIsNone(cfg.progress_callback)
        self.assertEqual(cfg.temperature, 1.0)
        self.assertEqual(cfg.top_p, 1.0)
        self.assertIsNone(cfg.seed)
        self.assertEqual(cfg.markov_smoothing_k, 0.0)

    def test_custom_values(self):
        from hashaxe.attacks import AttackConfig
        cb = lambda n: None
        cfg = AttackConfig(
            max_candidates=500,
            checkpoint_file="/tmp/ckpt.json",
            progress_callback=cb,
            temperature=0.7,
            top_p=0.9,
            seed=42,
            markov_smoothing_k=0.5,
        )
        self.assertEqual(cfg.max_candidates, 500)
        self.assertEqual(cfg.checkpoint_file, "/tmp/ckpt.json")
        self.assertIs(cfg.progress_callback, cb)
        self.assertAlmostEqual(cfg.temperature, 0.7)
        self.assertAlmostEqual(cfg.top_p, 0.9)
        self.assertEqual(cfg.seed, 42)
        self.assertAlmostEqual(cfg.markov_smoothing_k, 0.5)

    def test_backward_compatibility(self):
        """Old-style construction still works."""
        from hashaxe.attacks import AttackConfig
        cfg = AttackConfig(wordlist="/tmp/test.txt", max_length=20)
        self.assertEqual(cfg.wordlist, "/tmp/test.txt")
        self.assertEqual(cfg.max_length, 20)
        # New fields have defaults
        self.assertEqual(cfg.max_candidates, 0)


# ===========================================================================
# 2. AI Generator rate limiting
# ===========================================================================

class TestAIGeneratorRateLimit(unittest.TestCase):
    """AI generator respects max_candidates."""

    def test_markov_fallback_rate_limit(self):
        from hashaxe.attacks.ai_generator import AIGeneratorAttack
        from hashaxe.attacks import AttackConfig

        # Create a small wordlist
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for w in ["password", "hello", "world", "test", "admin"]:
                f.write(w + "\n")
            wl = f.name

        try:
            attack = AIGeneratorAttack()
            cfg = AttackConfig(
                wordlist=wl,
                max_candidates=3,
                max_length=20,
            )
            results = list(attack.generate(cfg))
            self.assertLessEqual(len(results), 3)
        finally:
            os.unlink(wl)

    def test_progress_callback(self):
        from hashaxe.attacks.ai_generator import AIGeneratorAttack
        from hashaxe.attacks import AttackConfig

        counts = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for w in ["password", "hello"]:
                f.write(w + "\n")
            wl = f.name

        try:
            attack = AIGeneratorAttack()
            cfg = AttackConfig(
                wordlist=wl,
                max_candidates=5,
                max_length=20,
                progress_callback=lambda n: counts.append(n),
            )
            list(attack.generate(cfg))
            self.assertGreater(len(counts), 0)
        finally:
            os.unlink(wl)


# ===========================================================================
# 3. Markov Add-k Smoothing
# ===========================================================================

class TestMarkovSmoothing(unittest.TestCase):
    """Markov chain attack with Add-k smoothing."""

    def _make_wordlist(self, words):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        for w in words:
            f.write(w + "\n")
        f.close()
        return f.name

    def test_no_smoothing(self):
        from hashaxe.attacks.markov import MarkovAttack
        from hashaxe.attacks import AttackConfig

        wl = self._make_wordlist(["abc", "abd", "abe"])
        try:
            attack = MarkovAttack()
            cfg = AttackConfig(
                wordlist=wl, max_candidates=10,
                max_length=5, markov_smoothing_k=0.0,
            )
            results = list(attack.generate(cfg))
            self.assertGreater(len(results), 0)
        finally:
            os.unlink(wl)

    def test_with_smoothing(self):
        from hashaxe.attacks.markov import MarkovAttack
        from hashaxe.attacks import AttackConfig

        wl = self._make_wordlist(["abc", "abd", "abe"])
        try:
            attack = MarkovAttack()
            cfg = AttackConfig(
                wordlist=wl, max_candidates=10,
                max_length=5, markov_smoothing_k=1.0,
            )
            results = list(attack.generate(cfg))
            self.assertGreater(len(results), 0)
        finally:
            os.unlink(wl)

    def test_rate_limiting(self):
        from hashaxe.attacks.markov import MarkovAttack
        from hashaxe.attacks import AttackConfig

        wl = self._make_wordlist(["test", "pass", "word"])
        try:
            attack = MarkovAttack()
            cfg = AttackConfig(wordlist=wl, max_candidates=2, max_length=6)
            results = list(attack.generate(cfg))
            self.assertLessEqual(len(results), 2)
        finally:
            os.unlink(wl)


# ===========================================================================
# 4. PRINCE Deduplication
# ===========================================================================

class TestPrinceDedup(unittest.TestCase):
    """PRINCE attack de-duplicates candidates."""

    def test_no_duplicates(self):
        from hashaxe.attacks.prince import PrinceAttack
        from hashaxe.attacks import AttackConfig

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            # Deliberately repeat words
            for w in ["ab", "ab", "cd", "cd"]:
                f.write(w + "\n")
            wl = f.name

        try:
            attack = PrinceAttack()
            cfg = AttackConfig(
                wordlist=wl, prince_min_elems=1, prince_max_elems=1,
                max_candidates=100, max_length=10,
            )
            results = list(attack.generate(cfg))
            self.assertEqual(len(results), len(set(results)))
        finally:
            os.unlink(wl)

    def test_rate_limiting(self):
        from hashaxe.attacks.prince import PrinceAttack
        from hashaxe.attacks import AttackConfig

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for w in ["a", "b", "c", "d", "e"]:
                f.write(w + "\n")
            wl = f.name

        try:
            attack = PrinceAttack()
            cfg = AttackConfig(
                wordlist=wl, prince_min_elems=1, prince_max_elems=2,
                max_candidates=3, max_length=10,
            )
            results = list(attack.generate(cfg))
            self.assertLessEqual(len(results), 3)
        finally:
            os.unlink(wl)


# ===========================================================================
# 5. PCFG Keyboard-Walk Tokenization
# ===========================================================================

class TestPCFGKeyboardWalk(unittest.TestCase):
    """PCFG tokenizer detects keyboard-walk patterns."""

    def test_qwerty_detected(self):
        from hashaxe.attacks.pcfg import _tokenize
        tokens = _tokenize("qwerty123")
        classes = [cls for cls, _ in tokens]
        self.assertIn("K", classes, "Expected keyboard-walk 'K' class for 'qwerty'")

    def test_asdf_detected(self):
        from hashaxe.attacks.pcfg import _tokenize
        tokens = _tokenize("asdf!!")
        classes = [cls for cls, _ in tokens]
        self.assertIn("K", classes)

    def test_normal_word_no_keyboard_walk(self):
        from hashaxe.attacks.pcfg import _tokenize
        tokens = _tokenize("hello")
        classes = [cls for cls, _ in tokens]
        self.assertNotIn("K", classes)

    def test_structure_key_includes_k(self):
        from hashaxe.attacks.pcfg import _tokenize, _structure_key
        tokens = _tokenize("qwerty123")
        key = _structure_key(tokens)
        self.assertIn("K", key)


# ===========================================================================
# 6. Distributed Master Path Traversal Validation
# ===========================================================================

class TestDistributedPathValidation(unittest.TestCase):
    """Distributed master rejects path traversal."""

    def test_traversal_rejected(self):
        from hashaxe.distributed.master import _validate_path
        with self.assertRaises(ValueError):
            _validate_path("../../etc/passwd", "test_path")

    def test_valid_path_accepted(self):
        from hashaxe.distributed.master import _validate_path
        # Use a path that exists
        result = _validate_path(__file__, "test_path")
        self.assertTrue(os.path.isabs(result))

    def test_nonexistent_rejected(self):
        from hashaxe.distributed.master import _validate_path
        with self.assertRaises(ValueError):
            _validate_path("/nonexistent/path/file.txt", "test_path")


# ===========================================================================
# 7. PQC Scanner — X.509 Method Existence
# ===========================================================================

class TestPQCScannerX509(unittest.TestCase):
    """PQC scanner has X.509 cert scanning capability."""

    def test_scan_x509_method_exists(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        self.assertTrue(hasattr(scanner, "scan_x509_cert"))

    def test_scan_x509_missing_file(self):
        from hashaxe.pqc.scanner import PQCScanner
        scanner = PQCScanner()
        result = scanner.scan_x509_cert("/nonexistent/cert.pem")
        self.assertEqual(result.asset_type, "certificate")
        self.assertIn("not found", result.details)

    def test_scan_algorithm_rsa(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk
        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        self.assertEqual(result.risk, QuantumRisk.VULNERABLE)


# ===========================================================================
# 8. Web3 Auditor — Solana Keypair Detection
# ===========================================================================

class TestWeb3SolanaKeypair(unittest.TestCase):
    """Web3 auditor detects Solana ed25519 keypairs."""

    def test_solana_keypair_detected(self):
        from hashaxe.web3.zk_auditor import ZKAuditor, WalletType

        # Create fake Solana id.json (64-byte array)
        fake_keypair = list(range(64))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(fake_keypair, f)
            wallet_path = f.name

        try:
            auditor = ZKAuditor()
            analysis = auditor.analyze_wallet(wallet_path)
            self.assertEqual(analysis.wallet_type, WalletType.SOLANA_KEYPAIR)
            self.assertEqual(analysis.kdf, "none")
            self.assertFalse(analysis.hashaxeable)
            # Should have findings
            self.assertGreater(len(analysis.findings), 0)
            severities = [f.severity.value for f in analysis.findings]
            self.assertIn("CRITICAL", severities)
        finally:
            os.unlink(wallet_path)

    def test_ethereum_not_affected(self):
        from hashaxe.web3.zk_auditor import ZKAuditor, WalletType

        eth_data = {
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {"n": 262144, "r": 8, "p": 1},
            },
            "address": "0xdeadbeef",
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(eth_data, f)
            wallet_path = f.name

        try:
            auditor = ZKAuditor()
            analysis = auditor.analyze_wallet(wallet_path)
            self.assertEqual(analysis.wallet_type, WalletType.ETHEREUM_V3)
        finally:
            os.unlink(wallet_path)


# ===========================================================================
# 9. Auto-Pwn Hardware Profiling
# ===========================================================================

class TestAutoPwnHardwareProfiling(unittest.TestCase):
    """Auto-pwn runs hardware profiling at pipeline start."""

    @patch("hashaxe.auto_pwn.hashaxe")
    @patch("hashaxe.gpu.accelerator.detect_gpu", return_value=None)
    def test_pipeline_profiles_hardware(self, mock_gpu, mock_hashaxe):
        from hashaxe.auto_pwn import AutoPwnOrchestrator

        mock_hashaxe.return_value = "found_password"
        orch = AutoPwnOrchestrator(
            key_path="/tmp/fake_key",
            wordlist_path="/tmp/fake_wordlist",
        )
        result = orch.execute_pipeline()
        self.assertEqual(result, "found_password")
        # GPU mocked to None so _has_gpu should be False
        self.assertFalse(orch._has_gpu)


# ===========================================================================
# 10. Distributed Master Heartbeat Requeue
# ===========================================================================

class TestDistributedHeartbeat(unittest.TestCase):
    """Distributed master requeues timed-out work items."""

    def test_master_has_heartbeat_param(self):
        """MasterNode accepts heartbeat_timeout parameter."""
        from hashaxe.distributed.master import MasterNode

        import inspect
        sig = inspect.signature(MasterNode.__init__)
        self.assertIn("heartbeat_timeout", sig.parameters)


if __name__ == "__main__":
    unittest.main()
