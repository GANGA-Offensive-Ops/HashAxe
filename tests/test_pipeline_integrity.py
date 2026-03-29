# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_pipeline_integrity.py
#  Pipeline integrity tests ensuring registry ↔ identify ↔ GPU routing consistency.
#  Verifies the central hash registry is the single source of truth.
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
tests/test_pipeline_integrity.py — Pipeline integrity validation.

Ensures:
  • Central registry loads all 42+ hash types
  • GPU HASHCAT_MODES dict is derived from (not duplicating) the registry
  • Format ID naming is consistent across identify/classify/hashaxe subsystems
  • NTLM/LM now appear in multi-candidate results
  • No format_id emitted by identify is unknown to the hashaxeing pipeline
"""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestRegistryIntegrity(unittest.TestCase):
    """Validate central hash registry completeness and accessor functions."""

    def test_registry_loads(self):
        from hashaxe.core.hash_registry import HASH_REGISTRY, registry_stats
        stats = registry_stats()
        self.assertGreaterEqual(stats["total_formats"], 42)
        self.assertGreaterEqual(stats["gpu_supported"], 40)
        self.assertGreaterEqual(stats["categories"], 7)

    def test_every_entry_has_format_id(self):
        from hashaxe.core.hash_registry import HASH_REGISTRY
        for fmt_id, ht in HASH_REGISTRY.items():
            self.assertEqual(fmt_id, ht.format_id, f"Key/value mismatch: {fmt_id}")
            self.assertTrue(ht.format_id, "Empty format_id found")

    def test_every_gpu_entry_has_hashcat_mode(self):
        from hashaxe.core.hash_registry import HASH_REGISTRY
        for fmt_id, ht in HASH_REGISTRY.items():
            if ht.gpu_supported:
                self.assertIsNotNone(
                    ht.hashcat_mode,
                    f"{fmt_id} is gpu_supported but has no hashcat_mode"
                )

    def test_get_hashcat_mode(self):
        from hashaxe.core.hash_registry import get_hashcat_mode
        self.assertEqual(get_hashcat_mode("hash.md5"), 0)
        self.assertEqual(get_hashcat_mode("hash.sha256"), 1400)
        self.assertEqual(get_hashcat_mode("hash.bcrypt"), 3200)
        self.assertEqual(get_hashcat_mode("network.ntlmv1"), 5500)
        self.assertEqual(get_hashcat_mode("network.ntlmv2"), 5600)
        self.assertIsNone(get_hashcat_mode("nonexistent.format"))

    def test_get_difficulty(self):
        from hashaxe.core.hash_registry import get_difficulty
        self.assertEqual(get_difficulty("hash.md5"), "TRIVIAL")
        self.assertEqual(get_difficulty("hash.bcrypt"), "SLOW")
        self.assertEqual(get_difficulty("hash.argon2"), "EXTREME")
        self.assertEqual(get_difficulty("nonexistent"), "unknown")

    def test_get_all_hashcat_modes_complete(self):
        from hashaxe.core.hash_registry import get_all_hashcat_modes
        modes = get_all_hashcat_modes()
        # Must include all formats from the old hardcoded dict
        required = [
            "hash.md5", "hash.sha1", "hash.sha256", "hash.sha512",
            "hash.ntlm", "hash.lm", "network.ntlmv1", "network.ntlmv2",
            "network.cisco_type5", "network.cisco_type8", "network.cisco_type9",
            "archive.7z", "archive.rar", "archive.zip",
            # NEW formats that were previously missing:
            "hash.bcrypt", "hash.mysql", "hash.jwt",
            "network.dcc1", "network.dcc2",
            "network.krb5tgs_rc4", "network.krb5asrep_rc4",
            "disk.dpapi", "token.ansible_vault", "pwm.keepass",
        ]
        for fmt_id in required:
            self.assertIn(fmt_id, modes, f"{fmt_id} missing from hashcat modes")


class TestGPURoutingSync(unittest.TestCase):
    """Verify HASHCAT_MODES in fast_hash_hashaxeer derives from registry."""

    def test_gpu_modes_match_registry(self):
        from hashaxe.core.hash_registry import get_all_hashcat_modes
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES

        registry_modes = get_all_hashcat_modes()
        # Every registry GPU format must be in HASHCAT_MODES
        for fmt_id, mode in registry_modes.items():
            self.assertIn(fmt_id, HASHCAT_MODES, f"{fmt_id} not in HASHCAT_MODES")
            self.assertEqual(
                HASHCAT_MODES[fmt_id], mode,
                f"{fmt_id}: GPU mode {HASHCAT_MODES[fmt_id]} != registry {mode}"
            )

    def test_gpu_mode_count(self):
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES
        # Should have 42+ entries (41 from registry + hash.raw fallback)
        self.assertGreaterEqual(len(HASHCAT_MODES), 42)

    def test_is_fast_hash_consistent(self):
        from hashaxe.core.hash_registry import HASH_REGISTRY
        from hashaxe.gpu.fast_hash_hashaxeer import is_fast_hash
        for fmt_id, ht in HASH_REGISTRY.items():
            if ht.gpu_supported and ht.hashcat_mode is not None:
                self.assertTrue(
                    is_fast_hash(fmt_id),
                    f"{fmt_id} should be fast_hash but is_fast_hash() returns False"
                )


class TestNamingConsistency(unittest.TestCase):
    """Verify format_id naming is consistent across all subsystems."""

    def test_no_hash_netntlm_in_patterns(self):
        """Verify old naming hash.netntlmv* is gone from hash_patterns."""
        from hashaxe.identify.hash_patterns import _PATTERNS
        for pattern_tuple in _PATTERNS:
            fmt_id = pattern_tuple[1]
            self.assertNotIn(
                "hash.netntlm",
                fmt_id,
                f"Found old naming '{fmt_id}' in hash_patterns.py"
            )

    def test_no_hash_netntlm_in_classifier(self):
        """Verify old naming is gone from classifier dicts."""
        from hashaxe.identify.classifier import _HASHCAT_MODES, _DIFFICULTY_MAP
        for d in [_HASHCAT_MODES, _DIFFICULTY_MAP]:
            for key in d:
                self.assertNotIn(
                    "hash.netntlm",
                    key,
                    f"Found old naming '{key}' in classifier.py"
                )

    def test_no_hash_netntlm_in_estimator(self):
        """Verify old naming is gone from estimator benchmarks."""
        from hashaxe.identify.estimator import _BENCHMARKS
        for key in _BENCHMARKS:
            self.assertNotIn(
                "hash.netntlm",
                key,
                f"Found old naming '{key}' in estimator.py"
            )

    def test_canonical_ntlm_names_in_patterns(self):
        """Verify canonical naming network.ntlmv1/v2 is used."""
        from hashaxe.identify.hash_patterns import _PATTERNS
        ntlm_ids = [t[1] for t in _PATTERNS if "ntlm" in t[1].lower()]
        self.assertIn("network.ntlmv1", ntlm_ids)
        self.assertIn("network.ntlmv2", ntlm_ids)


class TestNTLMLMDetection(unittest.TestCase):
    """Verify NTLM/LM heuristic detection now works."""

    def test_ntlm_can_handle_returns_low_confidence(self):
        from hashaxe.formats.hash_raw import NTLMFormat
        handler = NTLMFormat()
        # NTLM of "password"
        md5_hash = hashlib.md5(b"password").hexdigest()
        match = handler.can_handle(md5_hash.encode())
        self.assertIsNotNone(match, "NTLMFormat.can_handle() should not return None for 32-hex")
        self.assertEqual(match.format_id, "hash.ntlm")
        self.assertAlmostEqual(match.confidence, 0.3)

    def test_lm_can_handle_returns_low_confidence(self):
        from hashaxe.formats.hash_raw import LMFormat
        handler = LMFormat()
        fake_lm = "a" * 32
        match = handler.can_handle(fake_lm.encode())
        self.assertIsNotNone(match, "LMFormat.can_handle() should not return None for 32-hex")
        self.assertEqual(match.format_id, "hash.lm")
        self.assertAlmostEqual(match.confidence, 0.25)

    def test_md5_still_wins_over_ntlm(self):
        """MD5 (0.7) should beat NTLM (0.3) in priority."""
        from hashaxe.formats.hash_raw import RawHashFormat, NTLMFormat
        md5_handler = RawHashFormat()
        ntlm_handler = NTLMFormat()
        test_hash = hashlib.md5(b"test").hexdigest()
        md5_match = md5_handler.can_handle(test_hash.encode())
        ntlm_match = ntlm_handler.can_handle(test_hash.encode())
        self.assertIsNotNone(md5_match)
        self.assertIsNotNone(ntlm_match)
        self.assertGreater(md5_match.confidence, ntlm_match.confidence)

    def test_ntlm_rejects_non_hex(self):
        from hashaxe.formats.hash_raw import NTLMFormat
        handler = NTLMFormat()
        self.assertIsNone(handler.can_handle(b"not a hex string at all"))

    def test_ntlm_rejects_wrong_length(self):
        from hashaxe.formats.hash_raw import NTLMFormat
        handler = NTLMFormat()
        self.assertIsNone(handler.can_handle(b"abcdef0123456789"))  # 16 chars, not 32


class TestE2EPipelineIntegrity(unittest.TestCase):
    """End-to-end pipeline: identify → route → verify consistency."""

    def test_md5_full_pipeline(self):
        """MD5 hash identified → parsed → verified correctly."""
        from hashaxe.formats.hash_raw import RawHashFormat
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES, is_fast_hash
        from hashaxe.identify import auto_identify

        md5_hash = hashlib.md5(b"password").hexdigest()

        # Identify
        result = auto_identify(md5_hash)
        self.assertIsNotNone(result)
        self.assertIn("md5", result.format_id.lower())

        # Route
        self.assertTrue(is_fast_hash("hash.md5"))
        self.assertEqual(HASHCAT_MODES["hash.md5"], 0)

        # Verify
        handler = RawHashFormat()
        target = handler.parse(md5_hash.encode())
        self.assertTrue(handler.verify(target, b"password"))
        self.assertFalse(handler.verify(target, b"wrong"))

    def test_sha256_full_pipeline(self):
        """SHA-256 hash identified → parsed → verified correctly."""
        from hashaxe.formats.hash_raw import RawHashFormat
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES, is_fast_hash
        from hashaxe.identify import auto_identify

        sha_hash = hashlib.sha256(b"admin123").hexdigest()

        result = auto_identify(sha_hash)
        self.assertIsNotNone(result)
        self.assertIn("sha256", result.format_id.lower())

        self.assertTrue(is_fast_hash("hash.sha256"))
        self.assertEqual(HASHCAT_MODES["hash.sha256"], 1400)

        handler = RawHashFormat()
        target = handler.parse(sha_hash.encode())
        self.assertTrue(handler.verify(target, b"admin123"))

    def test_bcrypt_identification_and_routing(self):
        """bcrypt identified → routed to GPU (was missing before refactor)."""
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES, is_fast_hash
        from hashaxe.identify import auto_identify

        bcrypt_hash = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        result = auto_identify(bcrypt_hash)
        self.assertIsNotNone(result)
        self.assertEqual(result.format_id, "hash.bcrypt")

        # NEW: bcrypt is now GPU-routable
        self.assertTrue(is_fast_hash("hash.bcrypt"))
        self.assertEqual(HASHCAT_MODES["hash.bcrypt"], 3200)

    def test_netntlm_naming_consistency(self):
        """NetNTLMv2 hash_patterns emits network.ntlmv2 (not hash.netntlmv2)."""
        from hashaxe.gpu.fast_hash_hashaxeer import HASHCAT_MODES
        from hashaxe.identify.hash_patterns import identify_best

        ntlm_hash = "user::DOMAIN:1122334455667788:aabbccddaabbccddaabbccddaabbccdd:1122334455667788aabb"
        result = identify_best(ntlm_hash)
        self.assertIsNotNone(result)
        self.assertEqual(result.format_id, "network.ntlmv2")

        # Must be routable via GPU
        self.assertIn("network.ntlmv2", HASHCAT_MODES)

    def test_new_gpu_formats_routable(self):
        """Verify all 13 previously-missing formats are now GPU-routable."""
        from hashaxe.gpu.fast_hash_hashaxeer import is_fast_hash
        new_formats = [
            "hash.bcrypt", "hash.mysql", "hash.jwt",
            "network.dcc1", "network.dcc2",
            "network.krb5tgs_rc4", "network.krb5asrep_rc4",
            "disk.dpapi", "token.ansible_vault", "pwm.keepass",
            "hash.scrypt", "hash.argon2",
        ]
        for fmt_id in new_formats:
            self.assertTrue(
                is_fast_hash(fmt_id),
                f"{fmt_id} should be GPU-routable after refactor"
            )


if __name__ == "__main__":
    unittest.main()
