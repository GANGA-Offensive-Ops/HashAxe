# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_t1_formats.py
#  Tests for Tier 1 format handlers: Kerberos, DCC, DPAPI.
#  Covers parsing, identification, verification, and edge cases for 8 handler classes.
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
Tests for Tier 1 format handlers: Kerberos, DCC, DPAPI.

Covers parsing, identification, verification, and edge cases for all 8
new handler classes to ensure production-grade correctness.

NOTE: Tests instantiate handlers directly rather than using the registry
singleton's reset/discover cycle, because Python caches imported modules
in sys.modules — a reset+rediscover won't re-execute module-level code.

GANGA Offensive Ops · Crack V1
"""
from __future__ import annotations

import hashlib
import hmac
import pytest

from hashaxe.formats.base import FormatDifficulty

# Direct imports — avoids singleton reset/discover issues
from hashaxe.formats.network_kerberos import (
    Kerberos5TGS_RC4Format,
    Kerberos5ASREP_RC4Format,
    Kerberos5TGS_AES128Format,
    Kerberos5TGS_AES256Format,
)
from hashaxe.formats.network_dcc import DCC1Format, DCC2Format
from hashaxe.formats.disk_dpapi import DPAPIMasterkeyV1Format, DPAPIMasterkeyV2Format


# ══════════════════════════════════════════════════════════════════════════════
# Kerberoast TGS-REP RC4 (hashcat -m 13100)
# ══════════════════════════════════════════════════════════════════════════════

class TestKerberosTGSRC4:
    """Tests for Kerberoast TGS-REP RC4 etype 23."""

    SAMPLE = (
        "$krb5tgs$23$*user$TESTLAB.LOCAL$test/spn*"
        "$aabbccdd11223344aabbccdd11223344"
        "$deadbeef0011223344556677"
    )

    def setup_method(self):
        self.handler = Kerberos5TGS_RC4Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_a_kerberos_hash") is None

    def test_parse_extracts_fields(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_id == "network.krb5tgs_rc4"
        assert target.format_data["username"] == "user"
        assert target.format_data["realm"] == "TESTLAB.LOCAL"
        assert target.format_data["spn"] == "test/spn"
        assert target.difficulty == FormatDifficulty.FAST

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            self.handler.parse(b"invalid_data")

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "13100" in info["Hashcat Mode"]
        assert "T1558.003" in info["MITRE"]

    def test_difficulty(self):
        assert self.handler.difficulty() == FormatDifficulty.FAST

    def test_format_identity(self):
        assert self.handler.format_id == "network.krb5tgs_rc4"
        assert "Kerberoast" in self.handler.format_name


# ══════════════════════════════════════════════════════════════════════════════
# AS-REP Roast (hashcat -m 18200)
# ══════════════════════════════════════════════════════════════════════════════

class TestASREPRoast:
    """Tests for AS-REP Roast RC4 etype 23."""

    SAMPLE = (
        "$krb5asrep$23$svc_sql@CORP.LOCAL:"
        "aabbccdd11223344aabbccdd11223344"
        "$deadbeef00112233"
    )

    def setup_method(self):
        self.handler = Kerberos5ASREP_RC4Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_no_domain(self):
        """AS-REP format sometimes has no domain after @."""
        sample = (
            "$krb5asrep$23$user:"
            "aabbccdd11223344aabbccdd11223344"
            "$deadbeef00112233"
        )
        match = self.handler.can_handle(sample.encode())
        assert match is not None

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_an_asrep_hash") is None

    def test_parse_extracts_fields(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_data["username"] == "svc_sql"
        assert target.format_data["domain"] == "CORP.LOCAL"

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "18200" in info["Hashcat Mode"]
        assert "T1558.004" in info["MITRE"]


# ══════════════════════════════════════════════════════════════════════════════
# Kerberos AES128/256 TGS
# ══════════════════════════════════════════════════════════════════════════════

class TestKerberosAES:
    """Tests for Kerberos AES128 (19600) and AES256 (19700) TGS."""

    AES128_SAMPLE = (
        "$krb5tgs$17$user$REALM.COM$*HTTP/web.realm.com*"
        "$aabbccdd11223344"
        "$deadbeef00112233aabbccdd"
    )
    AES256_SAMPLE = (
        "$krb5tgs$18$admin$CORP.LOCAL$*CIFS/fs.corp.local*"
        "$aabbccdd11223344"
        "$deadbeef00112233aabbccdd"
    )

    def setup_method(self):
        self.aes128 = Kerberos5TGS_AES128Format()
        self.aes256 = Kerberos5TGS_AES256Format()

    def test_aes128_can_handle(self):
        match = self.aes128.can_handle(self.AES128_SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_aes256_can_handle(self):
        match = self.aes256.can_handle(self.AES256_SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_aes128_parse(self):
        target = self.aes128.parse(self.AES128_SAMPLE.encode())
        assert target.format_data["etype"] == 17
        assert target.difficulty == FormatDifficulty.MEDIUM

    def test_aes256_parse(self):
        target = self.aes256.parse(self.AES256_SAMPLE.encode())
        assert target.format_data["etype"] == 18

    def test_aes128_display(self):
        target = self.aes128.parse(self.AES128_SAMPLE.encode())
        info = self.aes128.display_info(target)
        assert "19600" in info["Hashcat Mode"]

    def test_aes256_display(self):
        target = self.aes256.parse(self.AES256_SAMPLE.encode())
        info = self.aes256.display_info(target)
        assert "19700" in info["Hashcat Mode"]

    def test_cross_rejection(self):
        """AES128 handler should not match AES256 hash and vice versa."""
        assert self.aes128.can_handle(self.AES256_SAMPLE.encode()) is None
        assert self.aes256.can_handle(self.AES128_SAMPLE.encode()) is None


# ══════════════════════════════════════════════════════════════════════════════
# DCC v1 (hashcat -m 1100)
# ══════════════════════════════════════════════════════════════════════════════

class TestDCC1:
    """Tests for DCC MS Cache v1."""

    def setup_method(self):
        self.handler = DCC1Format()

    @staticmethod
    def _make_dcc1(password: str, username: str) -> str:
        """Generate a real DCC v1 hash for testing."""
        pw_utf16 = password.encode("utf-16-le")
        ntlm = hashlib.new("md4", pw_utf16).digest()
        user_lower = username.lower().encode("utf-16-le")
        dcc = hashlib.new("md4", ntlm + user_lower).digest()
        return f"{dcc.hex()}:{username}"

    def test_can_handle_valid(self):
        sample = self._make_dcc1("password", "Administrator")
        match = self.handler.can_handle(sample.encode())
        assert match is not None
        assert match.confidence == 0.88

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_a_dcc_hash") is None

    def test_verify_correct_password(self):
        sample = self._make_dcc1("Password123", "admin")
        target = self.handler.parse(sample.encode())
        assert self.handler.verify(target, b"Password123") is True

    def test_verify_wrong_password(self):
        sample = self._make_dcc1("Password123", "admin")
        target = self.handler.parse(sample.encode())
        assert self.handler.verify(target, b"wrongpass") is False

    def test_verify_full_same_as_verify(self):
        sample = self._make_dcc1("test", "user")
        target = self.handler.parse(sample.encode())
        assert self.handler.verify_full(target, b"test") is True
        assert self.handler.verify_full(target, b"wrong") is False

    def test_display_info(self):
        sample = self._make_dcc1("test", "user1")
        target = self.handler.parse(sample.encode())
        info = self.handler.display_info(target)
        assert "1100" in info["Hashcat Mode"]
        assert "T1003.005" in info["MITRE"]

    def test_difficulty(self):
        assert self.handler.difficulty() == FormatDifficulty.TRIVIAL


# ══════════════════════════════════════════════════════════════════════════════
# DCC2 (hashcat -m 2100)
# ══════════════════════════════════════════════════════════════════════════════

class TestDCC2:
    """Tests for DCC2 MS Cache v2."""

    SAMPLE = "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"

    def setup_method(self):
        self.handler = DCC2Format()

    def test_can_handle_valid(self):
        match = self.handler.can_handle(self.SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_can_handle_invalid(self):
        assert self.handler.can_handle(b"not_a_dcc2_hash") is None

    def test_parse_extracts_fields(self):
        target = self.handler.parse(self.SAMPLE.encode())
        assert target.format_data["username"] == "tom"
        assert target.format_data["iterations"] == 10240
        assert target.difficulty == FormatDifficulty.SLOW

    def test_parse_different_iterations(self):
        sample = "$DCC2$4096#admin#aabbccdd11223344aabbccdd11223344"
        target = self.handler.parse(sample.encode())
        assert target.format_data["iterations"] == 4096

    def test_display_info(self):
        target = self.handler.parse(self.SAMPLE.encode())
        info = self.handler.display_info(target)
        assert "2100" in info["Hashcat Mode"]
        assert "10240" in info["Algorithm"]

    def test_difficulty(self):
        assert self.handler.difficulty() == FormatDifficulty.SLOW


# ══════════════════════════════════════════════════════════════════════════════
# DPAPI
# ══════════════════════════════════════════════════════════════════════════════

class TestDPAPI:
    """Tests for DPAPI masterkey v1/v2 handlers."""

    V1_SAMPLE = (
        "$DPAPImk$1*1*S-1-5-21-111-222-333-1001*des3*sha1*4000"
        "*aabbccdd11223344*64*eeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
    )

    def setup_method(self):
        self.v1 = DPAPIMasterkeyV1Format()
        self.v2 = DPAPIMasterkeyV2Format()

    def test_v1_can_handle(self):
        match = self.v1.can_handle(self.V1_SAMPLE.encode())
        assert match is not None
        assert match.confidence == 1.0

    def test_v1_parse(self):
        target = self.v1.parse(self.V1_SAMPLE.encode())
        assert target.format_data["version"] == 1
        assert target.format_data["sid"] == "S-1-5-21-111-222-333-1001"
        assert target.format_data["rounds"] == 4000
        assert target.difficulty == FormatDifficulty.SLOW

    def test_v1_display_info(self):
        target = self.v1.parse(self.V1_SAMPLE.encode())
        info = self.v1.display_info(target)
        assert "15300" in info["Hashcat Mode"]
        assert "T1555.003" in info["MITRE"]

    def test_v2_not_matched_by_v1(self):
        v2_sample = self.V1_SAMPLE.replace("$DPAPImk$1", "$DPAPImk$2")
        assert self.v1.can_handle(v2_sample.encode()) is None

    def test_v2_can_handle(self):
        v2_sample = self.V1_SAMPLE.replace("$DPAPImk$1", "$DPAPImk$2")
        match = self.v2.can_handle(v2_sample.encode())
        assert match is not None

    def test_v1_difficulty(self):
        assert self.v1.difficulty() == FormatDifficulty.SLOW

    def test_v2_difficulty(self):
        assert self.v2.difficulty() == FormatDifficulty.SLOW

    def test_v2_display_info(self):
        v2_sample = self.V1_SAMPLE.replace("$DPAPImk$1", "$DPAPImk$2")
        target = self.v2.parse(v2_sample.encode())
        info = self.v2.display_info(target)
        assert "15900" in info["Hashcat Mode"]


# ══════════════════════════════════════════════════════════════════════════════
# Hash Pattern Identification Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestHashPatternIntegration:
    """Verify hash_patterns.py correctly identifies the new T1 formats."""

    def test_identify_kerberoast(self):
        from hashaxe.identify.hash_patterns import identify_best
        h = (
            "$krb5tgs$23$*user$TESTLAB.LOCAL$test/spn*"
            "$aabbccdd11223344aabbccdd11223344"
            "$deadbeef00112233"
        )
        result = identify_best(h)
        assert result is not None
        assert result.format_id == "network.krb5tgs_rc4"

    def test_identify_asrep(self):
        from hashaxe.identify.hash_patterns import identify_best
        h = (
            "$krb5asrep$23$user@DOMAIN.COM:"
            "aabbccdd11223344aabbccdd11223344"
            "$deadbeef00112233"
        )
        result = identify_best(h)
        assert result is not None
        assert result.format_id == "network.krb5asrep_rc4"

    def test_identify_dcc2(self):
        from hashaxe.identify.hash_patterns import identify_best
        result = identify_best("$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f")
        assert result is not None
        assert result.format_id == "network.dcc2"

    def test_identify_dcc1(self):
        from hashaxe.identify.hash_patterns import identify_best
        result = identify_best("4dd8965d1d476fa0d026722989a6b772:testuser")
        assert result is not None
        assert result.format_id == "network.dcc1"

    def test_identify_dpapi(self):
        from hashaxe.identify.hash_patterns import identify_best
        h = "$DPAPImk$1*1*S-1-5-21-111*des3*sha1*4000*aabb*64*ccdd"
        result = identify_best(h)
        assert result is not None
        assert result.format_id == "disk.dpapi"


# ══════════════════════════════════════════════════════════════════════════════
# Registry Integration (no reset — uses existing singleton)
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistryIntegration:
    """Verify the new handlers integrate cleanly with existing registry."""

    def test_total_handler_count(self):
        """34 handlers total after adding 8 new T1 handlers."""
        from hashaxe.formats._registry import FormatRegistry
        reg = FormatRegistry()
        reg.discover()
        assert len(reg) >= 34

    def test_all_new_handlers_discoverable(self):
        from hashaxe.formats._registry import FormatRegistry
        reg = FormatRegistry()
        reg.discover()
        new_ids = [
            "network.krb5tgs_rc4",
            "network.krb5asrep_rc4",
            "network.krb5tgs_aes128",
            "network.krb5tgs_aes256",
            "network.dcc1",
            "network.dcc2",
            "disk.dpapi_v1",
            "disk.dpapi_v2",
        ]
        for fid in new_ids:
            assert fid in reg, f"Handler {fid} not found in registry"
