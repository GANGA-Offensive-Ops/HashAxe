# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/mitre.py
#  MITRE ATT&CK Auto-Mapper for credential artifacts.
#  Maps hash types to techniques, tactics, and data sources for pentest reports.
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
hashaxe.identify.mitre — MITRE ATT&CK Auto-Mapper.

Maps identified hash types to MITRE ATT&CK techniques, tactics, and
data sources. This enables pentest reports to automatically include
ATT&CK references for found credential artifacts.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping for a hash/credential type."""

    technique_id: str
    technique_name: str
    tactic: str
    subtechnique: str = ""
    data_sources: list[str] = field(default_factory=list)
    description: str = ""
    url: str = ""


# ── MITRE ATT&CK Mapping Database ────────────────────────────────────────────

_MITRE_MAP: dict[str, list[MITREMapping]] = {
    # Kerberos
    "network.krb5tgs_rc4": [
        MITREMapping(
            technique_id="T1558.003",
            technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
            tactic="Credential Access",
            data_sources=["Active Directory", "Network Traffic"],
            description="TGS-REP tickets requested for service accounts with SPNs",
            url="https://attack.mitre.org/techniques/T1558/003/",
        ),
    ],
    "network.krb5asrep_rc4": [
        MITREMapping(
            technique_id="T1558.004",
            technique_name="Steal or Forge Kerberos Tickets: AS-REP Roasting",
            tactic="Credential Access",
            data_sources=["Active Directory", "Network Traffic"],
            description="Pre-auth disabled accounts targeted for offline cracking",
            url="https://attack.mitre.org/techniques/T1558/004/",
        ),
    ],
    "network.krb5tgs_aes128": [
        MITREMapping(
            technique_id="T1558.003",
            technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
            tactic="Credential Access",
            data_sources=["Active Directory"],
            description="AES128 TGS ticket — stronger encryption but still hashaxeable",
            url="https://attack.mitre.org/techniques/T1558/003/",
        ),
    ],
    "network.krb5tgs_aes256": [
        MITREMapping(
            technique_id="T1558.003",
            technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
            tactic="Credential Access",
            data_sources=["Active Directory"],
            description="AES256 TGS ticket — requires significant GPU resources",
            url="https://attack.mitre.org/techniques/T1558/003/",
        ),
    ],
    # Domain Cached Credentials
    "network.dcc1": [
        MITREMapping(
            technique_id="T1003.005",
            technique_name="OS Credential Dumping: Cached Domain Credentials",
            tactic="Credential Access",
            data_sources=["Windows Registry", "HKLM\\SECURITY"],
            description="MS Cache v1 — fast to hashaxe, found in pre-Vista systems",
            url="https://attack.mitre.org/techniques/T1003/005/",
        ),
    ],
    "network.dcc2": [
        MITREMapping(
            technique_id="T1003.005",
            technique_name="OS Credential Dumping: Cached Domain Credentials",
            tactic="Credential Access",
            data_sources=["Windows Registry", "HKLM\\SECURITY"],
            description="MS Cache v2 (PBKDF2) — slower cracking, Vista+ systems",
            url="https://attack.mitre.org/techniques/T1003/005/",
        ),
    ],
    # DPAPI
    "disk.dpapi": [
        MITREMapping(
            technique_id="T1555.004",
            technique_name="Credentials from Password Stores: Windows Credential Manager",
            tactic="Credential Access",
            data_sources=["Windows DPAPI", "Master Key Files"],
            description="DPAPI master key — unlocks Windows credential vaults",
            url="https://attack.mitre.org/techniques/T1555/004/",
        ),
    ],
    # NTLM
    "network.ntlmv2": [
        MITREMapping(
            technique_id="T1557.001",
            technique_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            tactic="Credential Access",
            data_sources=["Network Traffic", "LLMNR", "NBNS"],
            description="NetNTLMv2 captured via Responder or network sniffing",
            url="https://attack.mitre.org/techniques/T1557/001/",
        ),
    ],
    "network.ntlmv1": [
        MITREMapping(
            technique_id="T1557.001",
            technique_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            tactic="Credential Access",
            data_sources=["Network Traffic"],
            description="NetNTLMv1 — weaker than v2, faster to hashaxe",
            url="https://attack.mitre.org/techniques/T1557/001/",
        ),
    ],
    # Unix password hashes
    "hash.sha512crypt": [
        MITREMapping(
            technique_id="T1003.008",
            technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
            tactic="Credential Access",
            data_sources=["/etc/shadow", "Linux"],
            description="Linux shadow file hash — standard for modern distros",
            url="https://attack.mitre.org/techniques/T1003/008/",
        ),
    ],
    "hash.md5crypt": [
        MITREMapping(
            technique_id="T1003.008",
            technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
            tactic="Credential Access",
            data_sources=["/etc/shadow", "Linux"],
            description="Legacy md5crypt — fast to hashaxe on modern hardware",
            url="https://attack.mitre.org/techniques/T1003/008/",
        ),
    ],
    # Cisco
    "network.cisco_type5": [
        MITREMapping(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials in Files",
            tactic="Credential Access",
            data_sources=["Cisco running-config", "TFTP backups"],
            description="Cisco Type 5 enable secret from running-config",
            url="https://attack.mitre.org/techniques/T1552/001/",
        ),
    ],
    "network.cisco_type8": [
        MITREMapping(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials in Files",
            tactic="Credential Access",
            data_sources=["Cisco running-config"],
            description="Cisco Type 8 (PBKDF2) — modern IOS-XE",
            url="https://attack.mitre.org/techniques/T1552/001/",
        ),
    ],
    "network.cisco_type9": [
        MITREMapping(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials in Files",
            tactic="Credential Access",
            data_sources=["Cisco running-config"],
            description="Cisco Type 9 (scrypt) — strongest Cisco password type",
            url="https://attack.mitre.org/techniques/T1552/001/",
        ),
    ],
    # Ansible Vault
    "token.ansible_vault": [
        MITREMapping(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials in Files",
            tactic="Credential Access",
            data_sources=["Ansible playbooks", "Git repositories"],
            description="Ansible Vault secret — may contain API keys, passwords, SSH keys",
            url="https://attack.mitre.org/techniques/T1552/001/",
        ),
    ],
    # JWT
    "hash.jwt": [
        MITREMapping(
            technique_id="T1528",
            technique_name="Steal Application Access Token",
            tactic="Credential Access",
            data_sources=["Web Application", "API Tokens"],
            description="JWT with weak HMAC secret — enables token forgery",
            url="https://attack.mitre.org/techniques/T1528/",
        ),
    ],
}


def get_mitre_mappings(format_id: str) -> list[MITREMapping]:
    """Get MITRE ATT&CK mappings for a hash format.

    Args:
        format_id: The hash format identifier (e.g., 'network.krb5tgs_rc4')

    Returns:
        List of MITREMapping objects, or empty list if no mapping exists.
    """
    return _MITRE_MAP.get(format_id, [])


def get_all_mapped_formats() -> list[str]:
    """Return all format IDs that have MITRE mappings."""
    return sorted(_MITRE_MAP.keys())


def generate_mitre_report(format_ids: list[str]) -> str:
    """Generate a markdown report of MITRE mappings for given formats."""
    lines = ["# MITRE ATT&CK Mapping Report", ""]

    for fid in format_ids:
        mappings = get_mitre_mappings(fid)
        if not mappings:
            continue

        for m in mappings:
            lines.append(f"## {m.technique_id} — {m.technique_name}")
            lines.append(f"- **Tactic:** {m.tactic}")
            lines.append(f"- **Hash Format:** `{fid}`")
            lines.append(f"- **Description:** {m.description}")
            lines.append(f"- **Data Sources:** {', '.join(m.data_sources)}")
            if m.url:
                lines.append(f"- **Reference:** [{m.technique_id}]({m.url})")
            lines.append("")

    if len(lines) <= 2:
        lines.append("No MITRE ATT&CK mappings found for the provided formats.")

    return "\n".join(lines)
