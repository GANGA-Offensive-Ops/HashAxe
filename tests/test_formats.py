# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_formats.py
#  Test suite for format plugin system covering BaseFormat, FormatTarget, FormatRegistry.
#  Tests OpenSSH and PPK format identification, parsing, and verification.
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
tests/test_formats.py — Test suite for the format plugin system (Batch 1).

Tests:
  • BaseFormat contract (ABC cannot be instantiated)
  • FormatTarget serialisation (pickle round-trip)
  • FormatRegistry (registration, discovery, identification, singleton)
  • OpenSSHFormat (identification, parsing, verification)
  • PPKFormat (identification, parsing, verification)
  • Integration: full flow from raw bytes → identify → parse → verify

Requires test key fixtures in tests/keys/.
"""

from __future__ import annotations

import copy
import pickle
import unittest
from pathlib import Path

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatTarget,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
_KEYS_DIR = Path(__file__).parent.parent / "test_files"


# ══════════════════════════════════════════════════════════════════════════════
# Test BaseFormat ABC
# ══════════════════════════════════════════════════════════════════════════════


class TestBaseFormatABC(unittest.TestCase):
    """Verify that BaseFormat cannot be instantiated directly."""

    def test_cannot_instantiate_base(self):
        """BaseFormat is abstract — instantiation must raise TypeError."""
        with self.assertRaises(TypeError):
            BaseFormat()  # type: ignore[abstract]

    def test_subclass_must_implement_all_methods(self):
        """A subclass missing any abstract method cannot be instantiated."""

        class IncompleteFormat(BaseFormat):
            format_id = "test.incomplete"
            format_name = "Incomplete"

            def can_handle(self, data, path=None):
                return None

            def parse(self, data, path=None):
                return FormatTarget()

            # Missing verify() and verify_full()

        with self.assertRaises(TypeError):
            IncompleteFormat()  # type: ignore[abstract]

    def test_complete_subclass_instantiates(self):
        """A fully implemented subclass instantiates successfully."""

        class CompleteFormat(BaseFormat):
            format_id = "test.complete"
            format_name = "Complete Test"

            def can_handle(self, data, path=None):
                return None

            def parse(self, data, path=None):
                return FormatTarget()

            def verify(self, target, password):
                return False

            def verify_full(self, target, password):
                return False

        handler = CompleteFormat()
        self.assertEqual(handler.format_id, "test.complete")
        self.assertEqual(handler.difficulty(), FormatDifficulty.MEDIUM)


# ══════════════════════════════════════════════════════════════════════════════
# Test FormatTarget
# ══════════════════════════════════════════════════════════════════════════════


class TestFormatTarget(unittest.TestCase):
    """FormatTarget must be picklable and copyable (multiprocessing)."""

    def test_default_construction(self):
        target = FormatTarget()
        self.assertEqual(target.format_id, "")
        self.assertTrue(target.is_encrypted)
        self.assertEqual(target.difficulty, FormatDifficulty.MEDIUM)
        self.assertEqual(target.format_data, {})

    def test_construction_with_data(self):
        target = FormatTarget(
            format_id="ssh.openssh",
            display_name="OpenSSH RSA",
            source_path="/tmp/test.key",
            is_encrypted=True,
            difficulty=FormatDifficulty.MEDIUM,
            format_data={"key_type": "ssh-rsa", "rounds": 16},
        )
        self.assertEqual(target.format_id, "ssh.openssh")
        self.assertEqual(target.format_data["rounds"], 16)

    def test_pickle_round_trip(self):
        """FormatTarget must survive pickle serialisation (multiprocessing)."""
        target = FormatTarget(
            format_id="ssh.ppk",
            display_name="PPK v3",
            format_data={"version": "3", "kdf": "argon2id"},
        )
        pickled = pickle.dumps(target)
        restored = pickle.loads(pickled)
        self.assertEqual(restored.format_id, "ssh.ppk")
        self.assertEqual(restored.format_data["version"], "3")

    def test_deep_copy(self):
        """FormatTarget must support deep copy."""
        target = FormatTarget(format_data={"nested": {"a": 1}})
        copied = copy.deepcopy(target)
        copied.format_data["nested"]["a"] = 999
        self.assertEqual(target.format_data["nested"]["a"], 1)


# ══════════════════════════════════════════════════════════════════════════════
# Test FormatRegistry
# ══════════════════════════════════════════════════════════════════════════════


class TestFormatRegistry(unittest.TestCase):
    """Test the singleton registry and its operations."""

    def setUp(self):
        # Get the singleton and remember current state
        self.registry = FormatRegistry()

    def test_singleton(self):
        """FormatRegistry is a singleton — same instance everywhere."""
        r1 = FormatRegistry()
        r2 = FormatRegistry()
        self.assertIs(r1, r2)

    def test_register_and_get(self):
        """Registering a handler makes it retrievable by format_id."""

        class DummyFormat(BaseFormat):
            format_id = "test.dummy_registry"
            format_name = "Dummy"

            def can_handle(self, data, path=None):
                return None

            def parse(self, data, path=None):
                return FormatTarget()

            def verify(self, target, password):
                return False

            def verify_full(self, target, password):
                return False

        handler = DummyFormat()
        self.registry.register(handler)
        retrieved = self.registry.get("test.dummy_registry")
        self.assertIs(retrieved, handler)

    def test_register_empty_id_raises(self):
        """Registering a handler with empty format_id raises ValueError."""

        class NoIdFormat(BaseFormat):
            format_id = ""
            format_name = "No ID"

            def can_handle(self, data, path=None):
                return None

            def parse(self, data, path=None):
                return FormatTarget()

            def verify(self, target, password):
                return False

            def verify_full(self, target, password):
                return False

        with self.assertRaises(ValueError):
            self.registry.register(NoIdFormat())

    def test_auto_discover_finds_ssh_handlers(self):
        """Auto-discovery imports ssh_openssh and ssh_ppk modules."""
        self.registry.discover()
        self.assertIn("ssh.openssh", self.registry)
        self.assertIn("ssh.ppk", self.registry)

    def test_identify_returns_none_for_garbage(self):
        """Unrecognised data returns None from identify()."""
        result = self.registry.identify(b"this is not a key file at all")
        self.assertIsNone(result)

    def test_contains_operator(self):
        """The `in` operator works on the registry."""
        self.registry.discover()
        self.assertTrue("ssh.openssh" in self.registry)
        self.assertFalse("nonexistent.format" in self.registry)

    def test_len(self):
        """Registry length reflects number of registered handlers."""
        self.registry.discover()
        self.assertGreaterEqual(len(self.registry), 2)  # at least openssh + ppk


# ══════════════════════════════════════════════════════════════════════════════
# Test OpenSSH Format Handler
# ══════════════════════════════════════════════════════════════════════════════


class TestOpenSSHFormat(unittest.TestCase):
    """Test identification, parsing, and verification for OpenSSH keys."""

    @classmethod
    def setUpClass(cls):
        """Load the format handler from the registry."""
        registry = FormatRegistry()
        registry.discover()
        cls.handler = registry.get("ssh.openssh")
        assert cls.handler is not None, "OpenSSH handler not found in registry"

    def test_identify_openssh_new(self):
        """Identifies modern OpenSSH keys by magic header."""
        data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake data\n-----END OPENSSH PRIVATE KEY-----"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 1.0)
        self.assertEqual(match.format_id, "ssh.openssh")
        self.assertEqual(match.metadata["variant"], "openssh-new")

    def test_identify_legacy_rsa(self):
        """Identifies legacy RSA PEM keys."""
        data = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.metadata["variant"], "legacy-rsa")

    def test_identify_legacy_ecdsa(self):
        """Identifies legacy ECDSA PEM keys."""
        data = b"-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.metadata["variant"], "legacy-ecdsa")

    def test_identify_legacy_dsa(self):
        """Identifies legacy DSA PEM keys."""
        data = b"-----BEGIN DSA PRIVATE KEY-----\nfake\n-----END DSA PRIVATE KEY-----"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.metadata["variant"], "legacy-dsa")

    def test_reject_non_ssh(self):
        """Returns None for non-SSH data."""
        match = self.handler.can_handle(b"PuTTY-User-Key-File-3: ssh-rsa")
        self.assertIsNone(match)

    def test_reject_garbage(self):
        """Returns None for random bytes."""
        match = self.handler.can_handle(b"\x00\x01\x02garbage")
        self.assertIsNone(match)

    # ── Parse + verify with real fixtures ─────────────────────────────────

    @unittest.skipUnless(
        (_KEYS_DIR / "rsa_legacy_puppet.key").exists(),
        "Test fixture rsa_legacy_puppet.key not found",
    )
    def test_parse_legacy_rsa_fixture(self):
        """Parse a real legacy RSA key fixture."""
        key_path = _KEYS_DIR / "rsa_legacy_puppet.key"
        data = key_path.read_bytes()
        target = self.handler.parse(data, key_path)

        self.assertEqual(target.format_id, "ssh.openssh")
        self.assertTrue(target.is_encrypted)
        self.assertIn("key_type", target.format_data)
        self.assertIsNotNone(target._legacy_pk)

    @unittest.skipUnless(
        (_KEYS_DIR / "rsa_legacy_puppet.key").exists(),
        "Test fixture rsa_legacy_puppet.key not found",
    )
    def test_verify_correct_password(self):
        """Correct password passes both verify() and verify_full()."""
        key_path = _KEYS_DIR / "rsa_legacy_puppet.key"
        data = key_path.read_bytes()
        target = self.handler.parse(data, key_path)

        self.assertTrue(self.handler.verify(target, b"puppet"))
        self.assertTrue(self.handler.verify_full(target, b"puppet"))

    @unittest.skipUnless(
        (_KEYS_DIR / "rsa_legacy_puppet.key").exists(),
        "Test fixture rsa_legacy_puppet.key not found",
    )
    def test_verify_wrong_password(self):
        """Wrong password fails verify()."""
        key_path = _KEYS_DIR / "rsa_legacy_puppet.key"
        data = key_path.read_bytes()
        target = self.handler.parse(data, key_path)

        self.assertFalse(self.handler.verify(target, b"wrong_password"))

    @unittest.skipUnless(
        (_KEYS_DIR / "rsa_legacy_nopass.key").exists(),
        "Test fixture rsa_legacy_nopass.key not found",
    )
    def test_unencrypted_key_reports_not_encrypted(self):
        """Unencrypted keys have is_encrypted=False."""
        key_path = _KEYS_DIR / "rsa_legacy_nopass.key"
        data = key_path.read_bytes()
        target = self.handler.parse(data, key_path)

        self.assertFalse(target.is_encrypted)

    def test_display_info(self):
        """display_info() returns expected metadata keys."""
        target = FormatTarget(
            format_id="ssh.openssh",
            format_data={
                "key_type": "ssh-rsa",
                "cipher": "aes256-ctr",
                "kdf": "bcrypt",
                "rounds": 16,
            },
        )
        info = self.handler.display_info(target)
        self.assertIn("Type", info)
        self.assertIn("Cipher", info)
        self.assertIn("KDF", info)
        self.assertEqual(info["Rounds"], "16")


# ══════════════════════════════════════════════════════════════════════════════
# Test PPK Format Handler
# ══════════════════════════════════════════════════════════════════════════════


class TestPPKFormat(unittest.TestCase):
    """Test identification, parsing, and verification for PPK keys."""

    @classmethod
    def setUpClass(cls):
        registry = FormatRegistry()
        registry.discover()
        cls.handler = registry.get("ssh.ppk")
        assert cls.handler is not None, "PPK handler not found in registry"

    def test_identify_ppk_v2(self):
        """Identifies PPK v2 by header magic."""
        data = b"PuTTY-User-Key-File-2: ssh-rsa\nsome content"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 1.0)
        self.assertEqual(match.metadata["version"], "2")

    def test_identify_ppk_v3(self):
        """Identifies PPK v3 by header magic."""
        data = b"PuTTY-User-Key-File-3: ssh-rsa\nsome content"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 1.0)
        self.assertEqual(match.metadata["version"], "3")
        self.assertEqual(match.metadata["kdf"], "argon2id")

    def test_ppk_v3_takes_priority_over_v2(self):
        """PPK v3 is preferred when v3 header is present."""
        data = b"PuTTY-User-Key-File-3: ssh-rsa\nPuTTY-User-Key-File-2: ssh-rsa"
        match = self.handler.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.metadata["version"], "3")

    def test_reject_openssh(self):
        """PPK handler does not match OpenSSH keys."""
        data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
        match = self.handler.can_handle(data)
        self.assertIsNone(match)

    def test_reject_garbage(self):
        """PPK handler rejects random data."""
        match = self.handler.can_handle(b"totally random data")
        self.assertIsNone(match)

    def test_display_info(self):
        """display_info() returns PPK-specific metadata."""
        target = FormatTarget(
            format_id="ssh.ppk",
            format_data={
                "version": "3",
                "algorithm": "ssh-ed25519",
                "encryption": "aes256-cbc",
                "kdf": "argon2id",
                "comment": "test@example.com",
            },
        )
        info = self.handler.display_info(target)
        self.assertEqual(info["Type"], "PPK v3")
        self.assertEqual(info["Algorithm"], "ssh-ed25519")
        self.assertEqual(info["Comment"], "test@example.com")

    def test_difficulty_worst_case(self):
        """PPK handler reports EXTREME difficulty (v3 worst case)."""
        self.assertEqual(self.handler.difficulty(), FormatDifficulty.EXTREME)


# ══════════════════════════════════════════════════════════════════════════════
# Integration: Registry → Identify → Parse → Verify
# ══════════════════════════════════════════════════════════════════════════════


class TestFormatIntegration(unittest.TestCase):
    """End-to-end tests: raw bytes → identify → parse → verify."""

    @unittest.skipUnless(
        (_KEYS_DIR / "rsa_legacy_puppet.key").exists(),
        "Test fixture rsa_legacy_puppet.key not found",
    )
    def test_full_flow_rsa_legacy(self):
        """Full pipeline: identify RSA key → parse → verify password."""
        registry = FormatRegistry()

        key_path = _KEYS_DIR / "rsa_legacy_puppet.key"
        data = key_path.read_bytes()

        # Step 1: Identify
        match = registry.identify(data, key_path)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "ssh.openssh")
        self.assertEqual(match.confidence, 1.0)

        # Step 2: Parse
        handler = match.handler
        target = handler.parse(data, key_path)
        self.assertTrue(target.is_encrypted)

        # Step 3: Verify (wrong password)
        self.assertFalse(handler.verify(target, b"wrong"))

        # Step 4: Verify (correct password)
        self.assertTrue(handler.verify(target, b"puppet"))
        self.assertTrue(handler.verify_full(target, b"puppet"))

    @unittest.skipUnless(
        (_KEYS_DIR / "ecdsa_legacy_abc123.key").exists(),
        "Test fixture ecdsa_legacy_abc123.key not found",
    )
    def test_full_flow_ecdsa_legacy(self):
        """Full pipeline for ECDSA legacy key."""
        registry = FormatRegistry()

        key_path = _KEYS_DIR / "ecdsa_legacy_abc123.key"
        data = key_path.read_bytes()

        match = registry.identify(data, key_path)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "ssh.openssh")

        handler = match.handler
        target = handler.parse(data, key_path)
        self.assertTrue(target.is_encrypted)

        self.assertFalse(handler.verify(target, b"wrong"))
        self.assertTrue(handler.verify(target, b"abc123"))

    def test_identify_returns_none_for_text(self):
        """Plain text files are not identified as any format."""
        registry = FormatRegistry()
        result = registry.identify(b"Hello, world! This is just a text file.")
        self.assertIsNone(result)

    def test_identify_returns_none_for_binary_garbage(self):
        """Random binary data is not identified."""
        registry = FormatRegistry()
        result = registry.identify(bytes(range(256)))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
