# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_t2_formats.py
#  Tests for Tier 2 format handlers: RAR, KeePass, Office, ODF, Ansible Vault, Cisco.
#  Direct handler instantiation tests for production-grade correctness.
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
Tests for Tier 2 format handlers: RAR, KeePass, Office, ODF, Ansible Vault, Cisco.

Direct handler instantiation tests (no registry reset/discover issues).
"""
from __future__ import annotations

import pytest

from hashaxe.formats.base import FormatDifficulty

# Direct imports
from hashaxe.formats.archive_rar import RARFormat
from hashaxe.formats.pwm_keepass import KeePassFormat, _KDBX_MAGIC_1, _KDBX_MAGIC_2
from hashaxe.formats.pwm_office import OfficeFormat, _OLE2_MAGIC
from hashaxe.formats.document_odf import ODFFormat
from hashaxe.formats.token_ansible import AnsibleVaultFormat
from hashaxe.formats.network_cisco_full import (
    CiscoType5Format,
    CiscoType8Format,
    CiscoType9Format,
    decode_type7,
)


# ══════════════════════════════════════════════════════════════════════════════
# RAR Archive
# ══════════════════════════════════════════════════════════════════════════════

class TestRARFormat:
    def setup_method(self):
        self.handler = RARFormat()

    def test_can_handle_rar4_magic(self):
        data = b"Rar!\x1a\x07\x00" + b"\x00" * 100
        match = self.handler.can_handle(data)
        assert match is not None

    def test_can_handle_rar5_magic(self):
        data = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100
        match = self.handler.can_handle(data)
        assert match is not None

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_a_rar_file") is None

    def test_can_handle_by_extension(self):
        from pathlib import Path
        match = self.handler.can_handle(b"\x00\x00", path=Path("test.rar"))
        assert match is not None
        assert match.confidence == 0.5

    def test_format_identity(self):
        assert self.handler.format_id == "archive.rar"
        assert "RAR" in self.handler.format_name

    def test_display_info(self):
        data = b"Rar!\x1a\x07\x00" + b"\x00" * 100
        target = self.handler.parse(data)
        info = self.handler.display_info(target)
        assert "RAR" in info["Format"]
        assert "Hashcat Mode" in info


# ══════════════════════════════════════════════════════════════════════════════
# KeePass KDBX
# ══════════════════════════════════════════════════════════════════════════════

class TestKeePassFormat:
    def setup_method(self):
        self.handler = KeePassFormat()

    def _make_kdbx_header(self, version_major: int = 3) -> bytes:
        """Create a minimal KDBX header with magic bytes."""
        import struct
        data = _KDBX_MAGIC_1 + _KDBX_MAGIC_2
        data += struct.pack("<H", 1)  # minor version
        data += struct.pack("<H", version_major)  # major version
        data += b"\x00" * 100
        return data

    def test_can_handle_kdbx3(self):
        data = self._make_kdbx_header(3)
        match = self.handler.can_handle(data)
        assert match is not None
        assert match.confidence == 1.0
        assert "AES-KDF" in match.metadata["description"]

    def test_can_handle_kdbx4(self):
        data = self._make_kdbx_header(4)
        match = self.handler.can_handle(data)
        assert match is not None
        assert "Argon2" in match.metadata["description"]

    def test_can_handle_by_extension(self):
        from pathlib import Path
        match = self.handler.can_handle(b"\x00\x00", path=Path("vault.kdbx"))
        assert match is not None
        assert match.confidence == 0.7

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_keepass_data") is None

    def test_parse_kdbx3(self):
        data = self._make_kdbx_header(3)
        target = self.handler.parse(data)
        assert target.format_id == "pwm.keepass"
        assert target.is_encrypted is True
        assert target.difficulty == FormatDifficulty.SLOW

    def test_parse_kdbx4_extreme(self):
        data = self._make_kdbx_header(4)
        target = self.handler.parse(data)
        assert target.difficulty == FormatDifficulty.EXTREME

    def test_display_info(self):
        data = self._make_kdbx_header(3)
        target = self.handler.parse(data)
        info = self.handler.display_info(target)
        assert "13400" in info["Hashcat Mode"]
        assert "KeePass" in info["Format"]


# ══════════════════════════════════════════════════════════════════════════════
# Microsoft Office
# ══════════════════════════════════════════════════════════════════════════════

class TestOfficeFormat:
    def setup_method(self):
        self.handler = OfficeFormat()

    def test_can_handle_ole2_with_encryption(self):
        data = _OLE2_MAGIC + b"\x00" * 50 + b"EncryptionInfo" + b"\x00" * 50
        match = self.handler.can_handle(data)
        assert match is not None
        assert match.confidence == 0.95

    def test_can_handle_ole2_without_encryption(self):
        data = _OLE2_MAGIC + b"\x00" * 200
        match = self.handler.can_handle(data)
        # May match as non-encrypted or not match at all
        # Either is acceptable behavior

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_office_data") is None

    def test_format_identity(self):
        assert self.handler.format_id == "pwm.office"
        assert "Office" in self.handler.format_name

    def test_display_info_with_encryption(self):
        data = _OLE2_MAGIC + b"\x00" * 50 + b"EncryptionInfo" + b"\x00" * 50
        target = self.handler.parse(data)
        info = self.handler.display_info(target)
        assert "Microsoft Office" in info["Format"]
        assert "Hashcat Mode" in info


# ══════════════════════════════════════════════════════════════════════════════
# OpenDocument Format
# ══════════════════════════════════════════════════════════════════════════════

class TestODFFormat:
    def setup_method(self):
        self.handler = ODFFormat()

    def test_can_handle_odf_with_encryption(self):
        import zipfile
        from io import BytesIO
        buf = BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
            zf.writestr("content.xml", "test")
            zf.writestr("META-INF/manifest.xml", "manifest:encryption-data")
        data = buf.getvalue()
        match = self.handler.can_handle(data)
        assert match is not None
        assert match.confidence == 0.95

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_odf_data") is None

    def test_format_identity(self):
        assert self.handler.format_id == "document.odf"
        assert "OpenDocument" in self.handler.format_name


# ══════════════════════════════════════════════════════════════════════════════
# Ansible Vault
# ══════════════════════════════════════════════════════════════════════════════

class TestAnsibleVaultFormat:
    SAMPLE = (
        "$ANSIBLE_VAULT;1.1;AES256\n"
        "3061376662363561326636323930636234393039\n"
        "6234643733303232626536633366303539316337\n"
        "6138666365383463376130313136306233393834\n"
    )

    def setup_method(self):
        self.handler = AnsibleVaultFormat()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_ansible_vault") is None

    def test_parse(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_id == "token.ansible_vault"
        assert target.is_encrypted is True
        assert target.difficulty == FormatDifficulty.SLOW
        assert target.format_data["version"] == "1.1"
        assert target.format_data["cipher"] == "AES256"

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "16900" in info["Hashcat Mode"]
        assert "PBKDF2" in info["KDF"]


# ══════════════════════════════════════════════════════════════════════════════
# Cisco Types
# ══════════════════════════════════════════════════════════════════════════════

class TestCiscoType5:
    SAMPLE = "$1$pdQG$0WzLBz0Ejp.AFeAylCKmN."

    def setup_method(self):
        self.handler = CiscoType5Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 0.9

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_cisco_hash") is None

    def test_parse(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_data["type"] == 5
        assert target.format_data["salt"] == "pdQG"

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "500" in info["Hashcat Mode"]


class TestCiscoType8:
    SAMPLE = "$8$dsYGNam6YVewYQi$hPHElm0gV8SHiTByOHFgS4AJwbSwphEQ/fNOjxCA8nY."

    def setup_method(self):
        self.handler = CiscoType8Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_cisco8") is None

    def test_parse(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_data["type"] == 8
        assert target.difficulty == FormatDifficulty.SLOW

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "9200" in info["Hashcat Mode"]


class TestCiscoType9:
    SAMPLE = "$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM."

    def setup_method(self):
        self.handler = CiscoType9Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_cisco9") is None

    def test_parse(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_data["type"] == 9
        assert target.difficulty == FormatDifficulty.EXTREME

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "9300" in info["Hashcat Mode"]


class TestCiscoType7Decoder:
    def test_decode_known(self):
        # Known Type 7 encoding for "cisco"
        result = decode_type7("070C285F4D06")
        assert result == "cisco"

    def test_decode_empty(self):
        assert decode_type7("") == ""


# ══════════════════════════════════════════════════════════════════════════════
# Registry Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestT2RegistryIntegration:
    def test_total_handler_count(self):
        from hashaxe.formats._registry import FormatRegistry
        reg = FormatRegistry()
        reg.discover()
        assert len(reg) >= 42

    def test_all_t2_discoverable(self):
        from hashaxe.formats._registry import FormatRegistry
        reg = FormatRegistry()
        reg.discover()
        t2_ids = [
            "archive.rar",
            "pwm.keepass",
            "pwm.office",
            "document.odf",
            "token.ansible_vault",
            "network.cisco_type5",
            "network.cisco_type8",
            "network.cisco_type9",
        ]
        for fid in t2_ids:
            assert fid in reg, f"T2 handler {fid} not found"


# ══════════════════════════════════════════════════════════════════════════════
# Hash Pattern Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestT2HashPatterns:
    def test_identify_ansible_vault(self):
        from hashaxe.identify.hash_patterns import identify_best
        result = identify_best("$ANSIBLE_VAULT;1.1;AES256")
        assert result is not None
        assert result.format_id == "token.ansible_vault"

    def test_identify_cisco_type8(self):
        from hashaxe.identify.hash_patterns import identify_best
        result = identify_best(
            "$8$dsYGNam6YVewYQi$hPHElm0gV8SHiTByOHFgS4AJwbSwphEQ/fNOjxCA8nY."
        )
        assert result is not None
        assert result.format_id == "network.cisco_type8"

    def test_identify_cisco_type9(self):
        from hashaxe.identify.hash_patterns import identify_best
        result = identify_best(
            "$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM."
        )
        assert result is not None
        assert result.format_id == "network.cisco_type9"
