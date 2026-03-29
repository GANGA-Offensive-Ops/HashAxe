# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_network_db.py
#  Tests for network and database format handlers (MySQL, PostgreSQL, MSSQL, JWT, NetNTLM).
#  Covers detection, parsing, verification, and Argon2 parameter extraction.
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
Tests for Batch 5: Network & Database Format Handlers.

Coverage:
  - MySQL: SHA1(SHA1(pass)) detection + verification
  - PostgreSQL: MD5(pass+user) detection + verification
  - MSSQL: SHA-512 salted detection + verification
  - JWT: HMAC-SHA256/384/512 detection + verification
  - NetNTLMv2: challenge-response detection + verification
  - Argon2: parameter parsing + detection
  - scrypt: parameter parsing + detection
  - WPA: hccapx detection
  - Registry integration

GANGA Offensive Ops · Crack V3
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ══════════════════════════════════════════════════════════════════════════════
# MySQL Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMySQL(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.database_mysql import MySQLFormat
        return MySQLFormat()

    def test_detect_mysql_hash(self):
        h = self._handler()
        # SHA1(SHA1("password")) = *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
        pw_hash = "*" + hashlib.sha1(hashlib.sha1(b"password").digest()).hexdigest().upper()
        match = h.can_handle(pw_hash.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "database.mysql")

    def test_reject_non_mysql(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not a mysql hash"))

    def test_verify_correct(self):
        h = self._handler()
        pw_hash = "*" + hashlib.sha1(hashlib.sha1(b"test123").digest()).hexdigest().upper()
        target = h.parse(pw_hash.encode())
        self.assertTrue(h.verify(target, b"test123"))

    def test_verify_wrong(self):
        h = self._handler()
        pw_hash = "*" + hashlib.sha1(hashlib.sha1(b"test123").digest()).hexdigest().upper()
        target = h.parse(pw_hash.encode())
        self.assertFalse(h.verify(target, b"wrong"))

    def test_display_info(self):
        h = self._handler()
        pw_hash = "*" + hashlib.sha1(hashlib.sha1(b"x").digest()).hexdigest().upper()
        target = h.parse(pw_hash.encode())
        info = h.display_info(target)
        self.assertIn("Algorithm", info)


# ══════════════════════════════════════════════════════════════════════════════
# PostgreSQL Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPostgreSQL(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.database_postgres import PostgreSQLFormat
        return PostgreSQLFormat()

    def test_detect_pg_hash(self):
        h = self._handler()
        # md5 + MD5("password" + "postgres")
        expected = "md5" + hashlib.md5(b"passwordpostgres").hexdigest()
        match = h.can_handle(expected.encode())
        self.assertIsNotNone(match)

    def test_detect_pg_user_hash(self):
        h = self._handler()
        expected = "admin:md5" + hashlib.md5(b"passwordadmin").hexdigest()
        match = h.can_handle(expected.encode())
        self.assertIsNotNone(match)
        self.assertGreaterEqual(match.confidence, 0.9)

    def test_reject_non_pg(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not a pg hash"))

    def test_verify_correct(self):
        h = self._handler()
        expected = "testuser:md5" + hashlib.md5(b"secret123testuser").hexdigest()
        target = h.parse(expected.encode())
        self.assertTrue(h.verify(target, b"secret123"))

    def test_verify_wrong(self):
        h = self._handler()
        expected = "testuser:md5" + hashlib.md5(b"secret123testuser").hexdigest()
        target = h.parse(expected.encode())
        self.assertFalse(h.verify(target, b"wrong"))


# ══════════════════════════════════════════════════════════════════════════════
# MSSQL Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMSSQL(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.database_mssql import MSSQLFormat
        return MSSQLFormat()

    def _make_mssql_hash(self, password: str, salt: bytes = b"\x01\x02\x03\x04") -> str:
        pw_utf16 = password.encode("utf-16-le")
        h = hashlib.sha512(pw_utf16 + salt).hexdigest()
        return "0x0200" + salt.hex() + h

    def test_detect_mssql(self):
        h = self._handler()
        mssql_hash = self._make_mssql_hash("password")
        match = h.can_handle(mssql_hash.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "database.mssql")

    def test_reject_non_mssql(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not mssql"))

    def test_verify_correct(self):
        h = self._handler()
        mssql_hash = self._make_mssql_hash("test123")
        target = h.parse(mssql_hash.encode())
        self.assertTrue(h.verify(target, b"test123"))

    def test_verify_wrong(self):
        h = self._handler()
        mssql_hash = self._make_mssql_hash("test123")
        target = h.parse(mssql_hash.encode())
        self.assertFalse(h.verify(target, b"wrong"))


# ══════════════════════════════════════════════════════════════════════════════
# JWT Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestJWT(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.token_jwt import JWTFormat
        return JWTFormat()

    def _make_jwt(self, secret: str, alg: str = "HS256") -> str:
        """Create a valid JWT for testing."""
        from hashaxe.formats.token_jwt import _b64url_encode
        header = _b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}).encode())
        payload = _b64url_encode(json.dumps({"sub": "1234"}).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        hash_name = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}[alg]
        sig = hmac.new(secret.encode(), signing_input, hash_name).digest()
        sig_b64 = _b64url_encode(sig)
        return f"{header}.{payload}.{sig_b64}"

    def test_detect_jwt_hs256(self):
        h = self._handler()
        jwt_str = self._make_jwt("mysecret", "HS256")
        match = h.can_handle(jwt_str.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "token.jwt")

    def test_detect_jwt_hs512(self):
        h = self._handler()
        jwt_str = self._make_jwt("mysecret", "HS512")
        match = h.can_handle(jwt_str.encode())
        self.assertIsNotNone(match)

    def test_reject_non_jwt(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not.ajwt"))

    def test_verify_correct(self):
        h = self._handler()
        jwt_str = self._make_jwt("supersecret", "HS256")
        target = h.parse(jwt_str.encode())
        self.assertTrue(h.verify(target, b"supersecret"))

    def test_verify_wrong(self):
        h = self._handler()
        jwt_str = self._make_jwt("supersecret", "HS256")
        target = h.parse(jwt_str.encode())
        self.assertFalse(h.verify(target, b"wrongkey"))

    def test_verify_hs512(self):
        h = self._handler()
        jwt_str = self._make_jwt("mykey512", "HS512")
        target = h.parse(jwt_str.encode())
        self.assertTrue(h.verify(target, b"mykey512"))
        self.assertFalse(h.verify(target, b"wrong"))


# ══════════════════════════════════════════════════════════════════════════════
# NetNTLM Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNetNTLM(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.network_ntlm import NetNTLMFormat
        return NetNTLMFormat()

    def test_detect_ntlmv2(self):
        h = self._handler()
        # Minimal valid NTLMv2 format
        ntlm_str = "admin::WORKGROUP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
        match = h.can_handle(ntlm_str.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "network.netntlm")

    def test_reject_non_ntlm(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not an ntlm hash"))

    def test_parse_ntlmv2(self):
        h = self._handler()
        ntlm_str = "admin::DOMAIN:1122334455667788:" + "a" * 32 + ":" + "b" * 64
        target = h.parse(ntlm_str.encode())
        self.assertEqual(target.format_data["username"], "admin")
        self.assertEqual(target.format_data["domain"], "DOMAIN")

    def test_display_info(self):
        h = self._handler()
        ntlm_str = "user::DOM:1122334455667788:" + "a" * 32 + ":" + "b" * 64
        target = h.parse(ntlm_str.encode())
        info = h.display_info(target)
        self.assertEqual(info["Username"], "user")


# ══════════════════════════════════════════════════════════════════════════════
# Argon2 Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestArgon2(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.hash_argon2 import Argon2Format
        return Argon2Format()

    def test_detect_argon2id(self):
        h = self._handler()
        a2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ=$RdescudvJCsgt3ub+b+daw=="
        match = h.can_handle(a2_hash.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "hash.argon2")

    def test_detect_argon2i(self):
        h = self._handler()
        a2_hash = "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ=$RdescudvJCsgt3ub+b+daw=="
        match = h.can_handle(a2_hash.encode())
        self.assertIsNotNone(match)

    def test_reject_non_argon2(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"$2b$12$notan.argon2.hash"))

    def test_parse_params(self):
        h = self._handler()
        a2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ=$RdescudvJCsgt3ub+b+daw=="
        target = h.parse(a2_hash.encode())
        self.assertEqual(target.format_data["memory_cost"], 65536)
        self.assertEqual(target.format_data["time_cost"], 3)
        self.assertEqual(target.format_data["parallelism"], 4)

    def test_display_info(self):
        h = self._handler()
        a2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ=$RdescudvJCsgt3ub+b+daw=="
        target = h.parse(a2_hash.encode())
        info = h.display_info(target)
        self.assertEqual(info["Memory"], "65,536 KiB")


# ══════════════════════════════════════════════════════════════════════════════
# scrypt Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestScrypt(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.hash_scrypt import ScryptFormat
        return ScryptFormat()

    def _make_scrypt_hash(self, password: str, salt: bytes = b"somesalt") -> str:
        n, r, p = 16384, 8, 1  # ln=14
        dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(dk).decode()
        return f"$scrypt$ln=14,r=8,p=1${salt_b64}${hash_b64}"

    def test_detect_scrypt(self):
        h = self._handler()
        scrypt_hash = self._make_scrypt_hash("test")
        match = h.can_handle(scrypt_hash.encode())
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "hash.scrypt")

    def test_reject_non_scrypt(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"$2b$12$notscrypt"))

    def test_verify_correct(self):
        h = self._handler()
        scrypt_hash = self._make_scrypt_hash("mypassword")
        target = h.parse(scrypt_hash.encode())
        self.assertTrue(h.verify(target, b"mypassword"))

    def test_verify_wrong(self):
        h = self._handler()
        scrypt_hash = self._make_scrypt_hash("mypassword")
        target = h.parse(scrypt_hash.encode())
        self.assertFalse(h.verify(target, b"wrong"))

    def test_parse_params(self):
        h = self._handler()
        scrypt_hash = self._make_scrypt_hash("x")
        target = h.parse(scrypt_hash.encode())
        self.assertEqual(target.format_data["n"], 16384)
        self.assertEqual(target.format_data["r"], 8)
        self.assertEqual(target.format_data["p"], 1)


# ══════════════════════════════════════════════════════════════════════════════
# WPA Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestWPA(unittest.TestCase):
    def _handler(self):
        from hashaxe.formats.network_wpa import WPAFormat
        return WPAFormat()

    def test_detect_hccapx(self):
        h = self._handler()
        hccapx_data = b"HCCAPX\x00\x00\x00\x04" + b"\x00" * 400
        match = h.can_handle(hccapx_data)
        self.assertIsNotNone(match)
        self.assertEqual(match.format_id, "network.wpa")

    def test_reject_non_wpa(self):
        h = self._handler()
        self.assertIsNone(h.can_handle(b"not a wpa capture"))

    def test_detect_pcap_low_confidence(self):
        h = self._handler()
        pcap_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100
        match = h.can_handle(pcap_data)
        self.assertIsNotNone(match)
        self.assertLessEqual(match.confidence, 0.5)

    def test_display_info(self):
        h = self._handler()
        from hashaxe.formats.base import FormatTarget
        target = FormatTarget(
            format_id="network.wpa",
            is_encrypted=True,
            format_data={"ssid": b"MyNetwork"},
        )
        info = h.display_info(target)
        self.assertEqual(info["SSID"], "MyNetwork")


# ══════════════════════════════════════════════════════════════════════════════
# Registry Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestBatch5Registry(unittest.TestCase):
    def test_all_batch5_in_registry(self):
        from hashaxe.formats._registry import FormatRegistry
        reg = FormatRegistry()
        reg.discover()
        expected = [
            "database.mysql", "hash.postgres", "database.mssql",
            "token.jwt", "network.netntlm",
            "hash.argon2", "hash.scrypt", "network.wpa",
        ]
        for fmt_id in expected:
            self.assertIn(fmt_id, reg, f"{fmt_id} not in registry")


if __name__ == "__main__":
    unittest.main()
