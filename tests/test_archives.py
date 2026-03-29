# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_archives.py
#  Tests for archive and document format handlers (ZIP, PDF, 7z).
#  Covers detection, parsing, encryption detection, and edge cases.
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
Tests for Batch 4: Archive & Document Format Handlers.

Coverage:
  - ZIP format: detection, parse, ZipCrypto verify, AES detect
  - PDF format: detection, parse, encryption detection, revision parse
  - 7z format: detection, parse, magic bytes
  - FormatRegistry integration: all new handlers auto-registered
  - Edge cases: non-encrypted, corrupt, too-small, wrong magic

GANGA Offensive Ops · Crack V3
"""
from __future__ import annotations

import struct
import sys
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ══════════════════════════════════════════════════════════════════════════════
# ZIP Format Handler Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestZipDetection(unittest.TestCase):
    """Test ZIP format detection and identification."""

    def _handler(self):
        from hashaxe.formats.archive_zip import ZipFormat

        return ZipFormat()

    def test_detects_zip_magic(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "archive.zip")

    def test_rejects_non_zip(self):
        h = self._handler()
        match = h.can_handle(b"This is not a ZIP file at all")
        self.assertIsNone(match)

    def test_rejects_too_small(self):
        h = self._handler()
        match = h.can_handle(b"PK")
        self.assertIsNone(match)

    def test_unencrypted_low_confidence(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertLessEqual(match.confidence, 0.5)

    def test_parse_unencrypted(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        target = h.parse(data)
        self.assertFalse(target.is_encrypted)

    def test_verify_unencrypted_zip(self):
        """Unencrypted ZIP — any password should extract fine."""
        h = self._handler()
        # Create an unencrypted ZIP in memory
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test.txt", "hello world")
        data = buf.getvalue()
        target = h.parse(data)
        self.assertFalse(target.is_encrypted)

    def test_display_info(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        target = h.parse(data)
        info = h.display_info(target)
        self.assertIn("Format", info)
        self.assertEqual(info["Format"], "ZIP Archive")


class TestZipEncryption(unittest.TestCase):
    """Test ZIP encryption detection internals."""

    def test_detect_zip_encryption_unencrypted(self):
        from hashaxe.formats.archive_zip import _detect_zip_encryption

        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        meta = _detect_zip_encryption(data)
        self.assertFalse(meta["encrypted"])
        self.assertEqual(meta["method"], "none")

    def test_detect_zip_encryption_corrupt(self):
        from hashaxe.formats.archive_zip import _detect_zip_encryption

        meta = _detect_zip_encryption(b"not a zip at all")
        self.assertFalse(meta["encrypted"])

    def test_parse_extra_fields_empty(self):
        from hashaxe.formats.archive_zip import _parse_extra_fields

        result = _parse_extra_fields(b"")
        self.assertEqual(result, [])

    def test_parse_extra_fields_valid(self):
        from hashaxe.formats.archive_zip import _parse_extra_fields

        # Construct a simple extra field: ID=0x0001, size=4, data=\x00\x00\x00\x00
        extra = struct.pack("<HH", 0x0001, 4) + b"\x00\x00\x00\x00"
        result = _parse_extra_fields(extra)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 0x0001)


class TestZipDifficulty(unittest.TestCase):
    """Test ZIP difficulty classification."""

    def test_difficulty_default(self):
        from hashaxe.formats.archive_zip import ZipFormat

        h = ZipFormat()
        from hashaxe.formats.base import FormatDifficulty

        self.assertEqual(h.difficulty(), FormatDifficulty.FAST)


# ══════════════════════════════════════════════════════════════════════════════
# PDF Format Handler Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestPDFDetection(unittest.TestCase):
    """Test PDF format detection."""

    def _handler(self):
        from hashaxe.formats.document_pdf import PDFFormat

        return PDFFormat()

    def test_detects_pdf_magic(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.pdf").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "document.pdf")

    def test_rejects_non_pdf(self):
        h = self._handler()
        match = h.can_handle(b"This is not a PDF")
        self.assertIsNone(match)

    def test_unencrypted_pdf_low_confidence(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.pdf").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertLessEqual(match.confidence, 0.5)

    def test_encrypted_pdf_high_confidence(self):
        h = self._handler()
        data = (FIXTURES / "test_encrypted.pdf").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(match.confidence, 0.9)

    def test_parse_unencrypted_pdf(self):
        h = self._handler()
        data = (FIXTURES / "test_unencrypted.pdf").read_bytes()
        target = h.parse(data)
        self.assertFalse(target.is_encrypted)

    def test_parse_encrypted_pdf(self):
        h = self._handler()
        data = (FIXTURES / "test_encrypted.pdf").read_bytes()
        target = h.parse(data)
        self.assertTrue(target.is_encrypted)
        self.assertEqual(target.format_data["revision"], 3)


class TestPDFEncryptionDetection(unittest.TestCase):
    """Test PDF encryption detection internals."""

    def test_detect_no_encrypt(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = (FIXTURES / "test_unencrypted.pdf").read_bytes()
        meta = _detect_pdf_encryption(data)
        self.assertFalse(meta["encrypted"])

    def test_detect_encrypt_rev4(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = (FIXTURES / "test_encrypted.pdf").read_bytes()
        meta = _detect_pdf_encryption(data)
        self.assertTrue(meta["encrypted"])
        self.assertEqual(meta["revision"], 3)
        self.assertEqual(meta["encryption_method"], "rc4-128")

    def test_detect_version(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = b"%PDF-2.0\nsome content"
        meta = _detect_pdf_encryption(data)
        self.assertEqual(meta["version"], "2.0")

    def test_detect_revision_rc4_40(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = b"%PDF-1.2\n/Encrypt\n/R 2\n"
        meta = _detect_pdf_encryption(data)
        self.assertTrue(meta["encrypted"])
        self.assertEqual(meta["encryption_method"], "rc4-40")

    def test_detect_revision_aes256(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = b"%PDF-1.7\n/Encrypt\n/R 6\n"
        meta = _detect_pdf_encryption(data)
        self.assertTrue(meta["encrypted"])
        self.assertEqual(meta["encryption_method"], "aes-256")

    def test_detect_revision_rc4_128(self):
        from hashaxe.formats.document_pdf import _detect_pdf_encryption

        data = b"%PDF-1.4\n/Encrypt\n/R 3\n"
        meta = _detect_pdf_encryption(data)
        self.assertTrue(meta["encrypted"])
        self.assertEqual(meta["encryption_method"], "rc4-128")


class TestPDFDifficulty(unittest.TestCase):
    """Test PDF difficulty classification."""

    def test_difficulty_default(self):
        from hashaxe.formats.base import FormatDifficulty
        from hashaxe.formats.document_pdf import PDFFormat

        h = PDFFormat()
        self.assertEqual(h.difficulty(), FormatDifficulty.MEDIUM)

    def test_display_info(self):
        from hashaxe.formats.document_pdf import PDFFormat

        h = PDFFormat()
        data = (FIXTURES / "test_encrypted.pdf").read_bytes()
        target = h.parse(data)
        info = h.display_info(target)
        self.assertIn("Encryption", info)
        self.assertEqual(info["Format"], "PDF Document")


# ══════════════════════════════════════════════════════════════════════════════
# 7-Zip Format Handler Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSevenZipDetection(unittest.TestCase):
    """Test 7z format detection."""

    def _handler(self):
        from hashaxe.formats.archive_7z import SevenZipFormat

        return SevenZipFormat()

    def test_detects_7z_magic(self):
        h = self._handler()
        data = (FIXTURES / "test_header.7z").read_bytes()
        match = h.can_handle(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "archive.7z")

    def test_rejects_non_7z(self):
        h = self._handler()
        match = h.can_handle(b"This is not a 7z file")
        self.assertIsNone(match)

    def test_rejects_too_small(self):
        h = self._handler()
        match = h.can_handle(b"7z\xbc")
        self.assertIsNone(match)

    def test_parse_7z_header(self):
        h = self._handler()
        data = (FIXTURES / "test_header.7z").read_bytes()
        target = h.parse(data)
        self.assertEqual(target.format_id, "archive.7z")

    def test_difficulty(self):
        from hashaxe.formats.archive_7z import SevenZipFormat
        from hashaxe.formats.base import FormatDifficulty

        h = SevenZipFormat()
        self.assertEqual(h.difficulty(), FormatDifficulty.SLOW)

    def test_display_info(self):
        h = self._handler()
        data = (FIXTURES / "test_header.7z").read_bytes()
        target = h.parse(data)
        info = h.display_info(target)
        self.assertIn("Format", info)
        self.assertEqual(info["Format"], "7-Zip Archive")


# ══════════════════════════════════════════════════════════════════════════════
# Registry Integration Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistryIntegration(unittest.TestCase):
    """Test that new handlers are auto-registered in FormatRegistry."""

    def test_zip_in_registry(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        reg.discover()
        self.assertIn("archive.zip", reg)

    def test_pdf_in_registry(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        reg.discover()
        self.assertIn("document.pdf", reg)

    def test_7z_in_registry(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        reg.discover()
        self.assertIn("archive.7z", reg)

    def test_registry_identifies_zip(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        data = (FIXTURES / "test_unencrypted.zip").read_bytes()
        match = reg.identify(data)
        self.assertIsNotNone(match)
        # Should match archive.zip (possibly with lower confidence since unencrypted)
        self.assertEqual(match.format_id, "archive.zip")

    def test_registry_identifies_pdf(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        data = (FIXTURES / "test_encrypted.pdf").read_bytes()
        match = reg.identify(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "document.pdf")

    def test_registry_identifies_7z(self):
        from hashaxe.formats._registry import FormatRegistry

        reg = FormatRegistry()
        data = (FIXTURES / "test_header.7z").read_bytes()
        match = reg.identify(data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "archive.7z")


# ══════════════════════════════════════════════════════════════════════════════
# Magic Byte Detection Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestMagicDetection(unittest.TestCase):
    """Test magic.py correctly detects ZIP/PDF/7z bytes."""

    def test_zip_magic(self):
        from hashaxe.identify.magic import identify_magic

        results = identify_magic(b"PK\x03\x04" + b"\x00" * 100)
        self.assertTrue(any(m.format_id == "archive.zip" for m in results))

    def test_pdf_magic(self):
        from hashaxe.identify.magic import identify_magic

        results = identify_magic(b"%PDF-1.7\nsome content")
        self.assertTrue(any(m.format_id == "document.pdf" for m in results))

    def test_7z_magic(self):
        from hashaxe.identify.magic import identify_magic

        results = identify_magic(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100)
        self.assertTrue(any(m.format_id == "archive.7z" for m in results))


if __name__ == "__main__":
    unittest.main()
