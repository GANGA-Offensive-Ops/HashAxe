# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/network_wpa.py
#  WPA/WPA2 handshake format handler for WiFi network cracking.
#  Uses PBKDF2-HMAC-SHA1 with 4096 iterations from hccapx/PCAP files.
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
WPA/WPA2 handshake format handler — PBKDF2-HMAC-SHA1 4096 iterations.

Parses hccapx files or PCAP files containing WPA 4-way handshakes.
The WPA key derivation:
  PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)
  PTK = PRF-512(PMK, ...)
  MIC = HMAC-MD5 or HMAC-SHA1(KCK, EAPOL frame)

Dependencies:
  - ``hashlib.pbkdf2_hmac`` (built-in)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import struct
from pathlib import Path
from typing import Optional

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# hccapx magic: HCCAPX\x00\x00\x00\x04
_HCCAPX_MAGIC = b"HCCAPX\x00\x00\x00\x04"
_HCCAPX_SIZE = 393  # Fixed size per record


def _prf_512(key: bytes, label: bytes, data: bytes) -> bytes:
    """PRF-512 as defined in IEEE 802.11i.

    Generates 64 bytes of keying material.
    """
    result = b""
    for i in range(4):
        result += hmac.new(
            key,
            label + b"\x00" + data + bytes([i]),
            hashlib.sha1,
        ).digest()
    return result[:64]


class WPAFormat(BaseFormat):
    """Handler for WPA/WPA2 handshake cracking from hccapx files.

    Algorithm: PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) → PMK
    Then PTK derivation → MIC comparison.
    """

    format_id = "network.wpa"
    format_name = "WPA/WPA2 Handshake"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Detect hccapx files by magic header."""
        if len(data) < 10:
            return None

        if data[:10] == _HCCAPX_MAGIC:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.95,
                metadata={"description": "WPA/WPA2 handshake (hccapx)"},
            )

        # Check for PCAP magic (we can't parse full PCAP yet, but detect it)
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": "PCAP file (may contain WPA handshake)"},
            )
        return None

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        """Parse hccapx record to extract WPA handshake data."""
        if data[:10] != _HCCAPX_MAGIC:
            return FormatTarget(
                format_id=self.format_id,
                display_name="WPA (unsupported capture format)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                format_data={"error": "Only hccapx format is currently supported"},
            )

        if len(data) < 144:  # Minimum needed for headers + eapol length
            return FormatTarget(
                format_id=self.format_id,
                display_name="WPA (Invalid)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                format_data={
                    "error": f"hccapx file too short (expected >= 144 bytes, got {len(data)})"
                },
            )

        # Parse hccapx structure (simplified)
        offset = 10
        # Signature version (4 bytes), message_pair (1 byte)
        _sig_ver = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        _msg_pair = data[offset]
        offset += 1

        # ESSID length + ESSID
        essid_len = data[offset]
        offset += 1
        essid = data[offset : offset + essid_len].decode("utf-8", "replace")
        offset += 32  # ESSID field is always 32 bytes overall

        # Key version (1 byte)
        _keyver = data[offset]
        offset += 1

        # KeyMIC (16 bytes)
        keymic = data[offset : offset + 16]
        offset += 16

        # AP MAC (6), STA MAC (6)
        ap_mac = data[offset : offset + 6]
        offset += 6
        sta_mac = data[offset : offset + 6]
        offset += 6

        # AP nonce (32), STA nonce (32)
        anonce = data[offset : offset + 32]
        offset += 32
        snonce = data[offset : offset + 32]
        offset += 32

        # EAPOL length + data
        eapol_len = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2
        eapol = data[offset : offset + eapol_len]

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"WPA2 ({essid})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.SLOW,
            format_data={
                "ssid": essid.encode("utf-8"),
                "keymic": keymic,
                "ap_mac": ap_mac,
                "sta_mac": sta_mac,
                "anonce": anonce,
                "snonce": snonce,
                "eapol": eapol,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """WPA verification:
        1. PMK = PBKDF2(SHA1, password, SSID, 4096, 32)
        2. PTK = PRF-512(PMK, "Pairwise key expansion", min(AP,STA) + max(AP,STA) + min(ANonce,SNonce) + max(ANonce,SNonce))
        3. KCK = PTK[:16]
        4. MIC = HMAC-MD5(KCK, EAPOL with zeroed MIC)
        5. Compare MIC
        """
        ssid = target.format_data["ssid"]
        expected_mic = target.format_data["keymic"]
        ap_mac = target.format_data["ap_mac"]
        sta_mac = target.format_data["sta_mac"]
        anonce = target.format_data["anonce"]
        snonce = target.format_data["snonce"]
        eapol = target.format_data["eapol"]

        # WPA passphrase: 8–63 ASCII characters
        pw_str = password.decode("utf-8", errors="replace")
        if len(pw_str) < 8 or len(pw_str) > 63:
            return False

        # Step 1: PMK
        pmk = hashlib.pbkdf2_hmac("sha1", password, ssid, 4096, dklen=32)

        # Step 2: PTK
        mac_pair = min(ap_mac, sta_mac) + max(ap_mac, sta_mac)
        nonce_pair = min(anonce, snonce) + max(anonce, snonce)
        ptk = _prf_512(pmk, b"Pairwise key expansion", mac_pair + nonce_pair)
        kck = ptk[:16]

        # Step 3: Zero the MIC field in EAPOL (bytes 77-93 typically)
        eapol_zeroed = bytearray(eapol)
        eapol_zeroed[81:97] = b"\x00" * 16  # Standard MIC position

        # Step 4: Compute MIC
        mic = hmac.new(kck, bytes(eapol_zeroed), hashlib.md5).digest()

        return hmac.compare_digest(mic, expected_mic)

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.SLOW

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        ssid = target.format_data.get("ssid", b"").decode("utf-8", "replace")
        return {
            "Algorithm": "PBKDF2-HMAC-SHA1 (4096 iterations)",
            "SSID": ssid,
            "Difficulty": "SLOW (hundreds pw/s)",
        }


_registry = FormatRegistry()
_registry.register(WPAFormat())
