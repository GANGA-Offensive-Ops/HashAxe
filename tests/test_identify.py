# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_identify.py
#  Tests for auto-identification engine covering entropy, hash patterns, magic bytes.
#  Tests raw hash format handlers including MD5, SHA, NTLM, bcrypt, Argon2.
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
Tests for Batch 2: Auto-Identification Engine + Raw Hash Formats.

Coverage:
  - Shannon entropy classifier
  - Hash pattern regex matcher
  - Magic byte detector
  - MagicIdentifier unified pipeline
  - RawHashFormat handler (MD5, SHA-256, SHA-512)
  - NTLMFormat handler
  - UnixCryptFormat handler
  - BcryptFormat handler
  - End-to-end: hash string → identify → parse → verify

GANGA Offensive Ops · Crack V3
"""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

# Ensure hashaxe is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ENTROPY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestEntropy(unittest.TestCase):
    """Test Shannon entropy calculator and charset classifier."""

    def test_empty_string_zero_entropy(self):
        from hashaxe.identify.entropy import shannon_entropy

        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_zero_entropy(self):
        from hashaxe.identify.entropy import shannon_entropy

        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)

    def test_high_entropy_random_hex(self):
        from hashaxe.identify.entropy import shannon_entropy

        # MD5 of "password" — should have high entropy
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        ent = shannon_entropy(h)
        self.assertGreater(ent, 3.0)

    def test_classify_hex_lower(self):
        from hashaxe.identify.entropy import classify_charset

        self.assertEqual(classify_charset("deadbeef0123456789"), "hex_lower")

    def test_classify_hex_mixed(self):
        from hashaxe.identify.entropy import classify_charset

        self.assertEqual(classify_charset("DeAdBeEf"), "hex_mixed")

    def test_classify_base64(self):
        from hashaxe.identify.entropy import classify_charset

        self.assertEqual(classify_charset("SGVsbG8gV29ybGQ="), "base64")

    def test_classify_printable(self):
        from hashaxe.identify.entropy import classify_charset

        self.assertEqual(classify_charset("Hello, World!"), "printable")

    def test_analyze_md5_is_likely_hash(self):
        from hashaxe.identify.entropy import analyze

        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = analyze(h)
        self.assertTrue(result.is_likely_hash)
        self.assertGreaterEqual(result.confidence, 0.5)

    def test_analyze_sha256_is_likely_hash(self):
        from hashaxe.identify.entropy import analyze

        h = hashlib.sha256(b"test").hexdigest()
        result = analyze(h)
        self.assertTrue(result.is_likely_hash)

    def test_analyze_short_string_not_hash(self):
        from hashaxe.identify.entropy import analyze

        result = analyze("hello")
        self.assertFalse(result.is_likely_hash)

    def test_suggest_hash_type_32(self):
        from hashaxe.identify.entropy import suggest_hash_type

        suggestions = suggest_hash_type("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIn("MD5", suggestions)

    def test_suggest_hash_type_64(self):
        from hashaxe.identify.entropy import suggest_hash_type

        h = hashlib.sha256(b"test").hexdigest()
        suggestions = suggest_hash_type(h)
        self.assertIn("SHA-256", suggestions)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. HASH PATTERN TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestHashPatterns(unittest.TestCase):
    """Test regex-based hash pattern identification."""

    def test_md5_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        m = identify_best("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.md5")

    def test_sha1_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = hashlib.sha1(b"test").hexdigest()
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha1")

    def test_sha256_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = hashlib.sha256(b"test").hexdigest()
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha256")

    def test_sha512_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = hashlib.sha512(b"test").hexdigest()
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha512")

    def test_bcrypt_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.bcrypt")

    def test_sha512crypt_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "$6$rounds=5000$saltsalt$" + "A" * 86
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha512crypt")

    def test_sha256crypt_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "$5$saltsalt$" + "A" * 43
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha256crypt")

    def test_md5crypt_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "$1$saltsalt$" + "A" * 22
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertIn("md5crypt", m.format_id)

    def test_mysql_native_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "*" + "A" * 40
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.mysql")

    def test_postgres_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "md5" + "a" * 32
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.postgres")

    def test_jwt_pattern(self):
        from hashaxe.identify.hash_patterns import identify_best

        h = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        m = identify_best(h)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.jwt")

    def test_shadow_line_extraction(self):
        from hashaxe.identify.hash_patterns import identify_best

        line = "root:$6$rounds=5000$saltsalt$" + "A" * 86 + ":18000:0:99999:7:::"
        m = identify_best(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "hash.sha512crypt")

    def test_empty_returns_none(self):
        from hashaxe.identify.hash_patterns import identify_best

        self.assertIsNone(identify_best(""))

    def test_garbage_returns_none(self):
        from hashaxe.identify.hash_patterns import identify_best

        self.assertIsNone(identify_best("not a hash at all"))

    def test_identify_all_returns_list(self):
        from hashaxe.identify.hash_patterns import identify_hash

        results = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. MAGIC BYTE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestMagicBytes(unittest.TestCase):
    """Test file magic byte detection."""

    def test_openssh_new_format(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"openssh-key-v1\x00" + b"\x00" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "ssh.openssh")

    def test_rsa_pem_header(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"A" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "ssh.openssh")

    def test_ppk_v3_header(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"PuTTY-User-Key-File-3: ssh-rsa\n" + b"A" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "ssh.ppk")

    def test_zip_magic(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"PK\x03\x04" + b"\x00" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "archive.zip")

    def test_pdf_magic(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"%PDF-1.4 " + b"\x00" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "document.pdf")

    def test_7z_magic(self):
        from hashaxe.identify.magic import identify_best_magic

        data = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100
        m = identify_best_magic(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.format_id, "archive.7z")

    def test_garbage_returns_none(self):
        from hashaxe.identify.magic import identify_best_magic

        self.assertIsNone(identify_best_magic(b"random garbage bytes"))

    def test_empty_returns_none(self):
        from hashaxe.identify.magic import identify_best_magic

        self.assertIsNone(identify_best_magic(b""))

    def test_real_ssh_key_fixture(self):
        from hashaxe.identify.magic import identify_magic_file

        key_path = Path(__file__).parent.parent / "test_files" / "rsa_legacy_puppet.key"
        if key_path.exists():
            matches = identify_magic_file(key_path)
            self.assertGreater(len(matches), 0)
            self.assertEqual(matches[0].format_id, "ssh.openssh")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MAGIC IDENTIFIER (UNIFIED PIPELINE) TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestMagicIdentifier(unittest.TestCase):
    """Test the MagicIdentifier unified pipeline."""

    def test_identify_md5_string(self):
        from hashaxe.identify import auto_identify

        result = auto_identify("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIsNotNone(result)
        self.assertIn("md5", result.format_id.lower())

    def test_identify_sha256_string(self):
        from hashaxe.identify import auto_identify

        h = hashlib.sha256(b"test").hexdigest()
        result = auto_identify(h)
        self.assertIsNotNone(result)
        self.assertIn("sha256", result.format_id.lower())

    def test_identify_bcrypt_string(self):
        from hashaxe.identify import auto_identify

        h = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        result = auto_identify(h)
        self.assertIsNotNone(result)
        self.assertEqual(result.format_id, "hash.bcrypt")

    def test_identify_ssh_key_file(self):
        from hashaxe.identify import auto_identify

        key_path = Path(__file__).parent.parent / "test_files" / "rsa_legacy_puppet.key"
        if key_path.exists():
            result = auto_identify(key_path)
            self.assertIsNotNone(result)
            self.assertEqual(result.source, "magic")
            self.assertEqual(result.format_id, "ssh.openssh")

    def test_identify_binary_bytes(self):
        from hashaxe.identify import auto_identify

        data = b"PK\x03\x04" + b"\x00" * 100
        result = auto_identify(data)
        self.assertIsNotNone(result)
        self.assertEqual(result.format_id, "archive.zip")

    def test_identify_nonsense_returns_none(self):
        from hashaxe.identify import auto_identify

        result = auto_identify("this is just regular text")
        self.assertIsNone(result)

    def test_identify_all_returns_list(self):
        from hashaxe.identify import auto_identify_all

        results = auto_identify_all("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. RAW HASH FORMAT HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestRawHashFormat(unittest.TestCase):
    """Test the RawHashFormat handler (MD5, SHA-256, SHA-512)."""

    def test_can_handle_md5(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        data = hashlib.md5(b"password").hexdigest().encode()
        match = handler.can_handle(data)
        self.assertIsNotNone(match)

    def test_can_handle_sha256(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        data = hashlib.sha256(b"password").hexdigest().encode()
        match = handler.can_handle(data)
        self.assertIsNotNone(match)

    def test_rejects_non_hex(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        self.assertIsNone(handler.can_handle(b"not a hex string"))

    def test_parse_md5(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        md5_hash = hashlib.md5(b"password").hexdigest()
        target = handler.parse(md5_hash.encode())
        self.assertTrue(target.is_encrypted)
        self.assertEqual(target.format_data["algorithm"], "md5")

    def test_verify_md5_correct(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        md5_hash = hashlib.md5(b"password").hexdigest()
        target = handler.parse(md5_hash.encode())
        self.assertTrue(handler.verify(target, b"password"))

    def test_verify_md5_wrong(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        md5_hash = hashlib.md5(b"password").hexdigest()
        target = handler.parse(md5_hash.encode())
        self.assertFalse(handler.verify(target, b"wrong"))

    def test_verify_sha256_correct(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        sha_hash = hashlib.sha256(b"secret123").hexdigest()
        target = handler.parse(sha_hash.encode())
        self.assertTrue(handler.verify(target, b"secret123"))

    def test_verify_sha512_correct(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        sha_hash = hashlib.sha512(b"test").hexdigest()
        target = handler.parse(sha_hash.encode())
        self.assertTrue(handler.verify(target, b"test"))

    def test_verify_full_equals_verify(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        md5_hash = hashlib.md5(b"test").hexdigest()
        target = handler.parse(md5_hash.encode())
        self.assertEqual(
            handler.verify(target, b"test"),
            handler.verify_full(target, b"test"),
        )

    def test_display_info(self):
        from hashaxe.formats.hash_raw import RawHashFormat

        handler = RawHashFormat()
        target = handler.parse(hashlib.md5(b"x").hexdigest().encode())
        info = handler.display_info(target)
        self.assertIn("Algorithm", info)
        self.assertIn("Hash", info)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. NTLM FORMAT HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestNTLMFormat(unittest.TestCase):
    """Test the NTLM format handler."""

    def test_parse_ntlm(self):
        from hashaxe.formats.hash_raw import NTLMFormat

        handler = NTLMFormat()
        # NTLM hash of "password" = a4f49c406510bdcab6824ee7c30fd852
        target = handler.parse(b"a4f49c406510bdcab6824ee7c30fd852")
        self.assertEqual(target.format_id, "hash.ntlm")
        self.assertTrue(target.is_encrypted)

    def test_verify_ntlm(self):
        from hashaxe.formats.hash_raw import NTLMFormat

        handler = NTLMFormat()
        # Pre-computed NTLM of "password"
        h = hashlib.new("md4", "password".encode("utf-16-le")).hexdigest()
        target = handler.parse(h.encode())
        try:
            result = handler.verify(target, b"password")
            self.assertTrue(result)
        except ValueError:
            self.skipTest("MD4 not available in this OpenSSL build")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. UNIX CRYPT FORMAT HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnixCryptFormat(unittest.TestCase):
    """Test Unix crypt format handler."""

    def test_can_handle_sha512crypt(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        h = "$6$rounds=5000$saltsalt$" + "A" * 86
        match = handler.can_handle(h.encode())
        self.assertIsNotNone(match)
        self.assertIn("sha512crypt", match.format_id)

    def test_can_handle_md5crypt(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        h = "$1$saltsalt$" + "A" * 22
        match = handler.can_handle(h.encode())
        self.assertIsNotNone(match)
        self.assertIn("md5crypt", match.format_id)

    def test_rejects_non_crypt(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        self.assertIsNone(handler.can_handle(b"not a crypt hash"))

    def test_parse_sha512crypt(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        h = "$6$rounds=5000$saltsalt$" + "A" * 86
        target = handler.parse(h.encode())
        self.assertEqual(target.format_data["variant"], "sha512crypt")
        self.assertEqual(target.format_data["rounds"], 5000)
        self.assertTrue(target.is_encrypted)

    def test_parse_shadow_line(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        line = "root:$6$rounds=5000$saltsalt$" + "A" * 86 + ":18000:0:99999:7:::"
        target = handler.parse(line.encode())
        self.assertEqual(target.format_data["variant"], "sha512crypt")

    def test_display_info(self):
        from hashaxe.formats.hash_unix import UnixCryptFormat

        handler = UnixCryptFormat()
        h = "$6$rounds=5000$saltsalt$" + "A" * 86
        target = handler.parse(h.encode())
        info = handler.display_info(target)
        self.assertIn("Variant", info)
        self.assertIn("Salt", info)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. BCRYPT FORMAT HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestBcryptFormat(unittest.TestCase):
    """Test bcrypt format handler."""

    def test_can_handle_bcrypt(self):
        from hashaxe.formats.hash_bcrypt import BcryptFormat

        handler = BcryptFormat()
        h = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        match = handler.can_handle(h.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "hash.bcrypt")

    def test_rejects_non_bcrypt(self):
        from hashaxe.formats.hash_bcrypt import BcryptFormat

        handler = BcryptFormat()
        self.assertIsNone(handler.can_handle(b"not a bcrypt hash"))

    def test_parse_bcrypt(self):
        from hashaxe.formats.hash_bcrypt import BcryptFormat

        handler = BcryptFormat()
        h = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        target = handler.parse(h.encode())
        self.assertEqual(target.format_data["cost"], 12)
        self.assertEqual(target.format_data["variant"], "b")
        self.assertTrue(target.is_encrypted)

    def test_display_info(self):
        from hashaxe.formats.hash_bcrypt import BcryptFormat

        handler = BcryptFormat()
        h = "$2b$12$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        target = handler.parse(h.encode())
        info = handler.display_info(target)
        self.assertIn("Variant", info)
        self.assertIn("Cost", info)
        self.assertEqual(info["Cost"], "12")

    def test_difficulty_by_cost(self):
        from hashaxe.formats.base import FormatDifficulty
        from hashaxe.formats.hash_bcrypt import BcryptFormat

        handler = BcryptFormat()
        h = "$2b$16$LJ3m4ys3Lk0TdcjFOIZFT.ZjFp8H.8xKJGo9/rviO78AxVfab/fq6"
        target = handler.parse(h.encode())
        self.assertEqual(target.difficulty, FormatDifficulty.EXTREME)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. END-TO-END INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestE2EHashCrack(unittest.TestCase):
    """End-to-end: hash string → identify → parse → verify."""

    def test_e2e_md5_hashaxe(self):
        """Feed an MD5 hash → auto-identify → parse → verify correct password."""
        from hashaxe.formats.hash_raw import RawHashFormat
        from hashaxe.identify import auto_identify

        # MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        md5_hash = hashlib.md5(b"password").hexdigest()

        # Step 1: Identify
        result = auto_identify(md5_hash)
        self.assertIsNotNone(result)
        self.assertIn("md5", result.format_id.lower())

        # Step 2: Parse
        handler = RawHashFormat()
        target = handler.parse(md5_hash.encode())
        self.assertTrue(target.is_encrypted)

        # Step 3: Verify
        self.assertTrue(handler.verify(target, b"password"))
        self.assertFalse(handler.verify(target, b"wrong"))

    def test_e2e_sha256_hashaxe(self):
        from hashaxe.formats.hash_raw import RawHashFormat
        from hashaxe.identify import auto_identify

        sha_hash = hashlib.sha256(b"admin123").hexdigest()
        result = auto_identify(sha_hash)
        self.assertIsNotNone(result)
        self.assertIn("sha256", result.format_id.lower())

        handler = RawHashFormat()
        target = handler.parse(sha_hash.encode())
        self.assertTrue(handler.verify(target, b"admin123"))
        self.assertFalse(handler.verify(target, b"admin"))


if __name__ == "__main__":
    unittest.main()
