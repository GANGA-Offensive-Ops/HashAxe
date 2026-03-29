# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/report.py
#  Pentest Report Generator for professional cracking result documentation.
#  Outputs markdown with executive summary, MITRE mappings, and remediation.
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
hashaxe.identify.report — Pentest Report Generator.

Generates professional pentest-quality reports from cracking results.
Supports markdown output format with executive summary, technical
findings, MITRE mappings, and remediation guidance.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from hashaxe.identify.classifier import ClassifiedHash, classify
from hashaxe.identify.mitre import get_mitre_mappings, MITREMapping
from hashaxe.identify.estimator import estimate_time, KEYSPACE

log = logging.getLogger(__name__)


@dataclass
class CrackResult:
    """Individual cracking result for report inclusion."""
    hash_value: str
    format_id: str
    algorithm: str
    cracked: bool = False
    password: str = ""
    time_taken: float = 0.0
    attack_mode: str = ""
    hashcat_mode: int | None = None


@dataclass
class ReportConfig:
    """Report generation configuration."""
    title: str = "Password Cracking Assessment Report"
    assessor: str = "Hashaxe V1"
    target: str = "Assessment Target"
    date: str = ""
    classification: str = "CONFIDENTIAL"
    include_mitre: bool = True
    include_remediation: bool = True


_REMEDIATION: dict[str, str] = {
    "hash.md5": "Migrate to bcrypt, scrypt, or Argon2. MD5 is cryptographically broken and should never be used for password storage.",
    "hash.sha1": "Migrate to bcrypt, scrypt, or Argon2. SHA-1 is deprecated for password hashing.",
    "hash.sha256": "Use with proper salting and high iteration count (PBKDF2-SHA256), or migrate to bcrypt/Argon2.",
    "hash.md5crypt": "Upgrade to sha512crypt ($6$) with high rounds, or bcrypt/Argon2.",
    "hash.sha512crypt": "Increase rounds to ≥100000. Consider migration to Argon2 for new deployments.",
    "hash.bcrypt": "Ensure cost factor ≥12. bcrypt is still considered secure with appropriate cost.",
    "hash.argon2": "Ensure memory parameter ≥64MB and time parameter ≥3. Argon2id is recommended variant.",
    "hash.mysql": "Upgrade to caching_sha2_password (MySQL 8.0+). mysql_native_password uses unsalted double-SHA1.",
    "network.ntlmv2": "Disable LLMNR and NBT-NS. Enforce SMB signing. Use EPA (Extended Protection for Authentication).",
    "network.ntlmv1": "CRITICAL: Disable NTLMv1 immediately. Enforce NTLMv2 minimum. Migrate to Kerberos.",
    "network.krb5tgs_rc4": "Disable RC4 encryption for Kerberos (etype 23). Enforce AES-256 minimum. Review service account passwords.",
    "network.krb5asrep_rc4": "Enable Kerberos pre-authentication for ALL accounts. Disable RC4 encryption.",
    "network.dcc1": "Upgrade domain controllers. DCC v1 is used by pre-Vista systems.",
    "network.dcc2": "Enforce strong password policy (≥14 chars). Limit cached credentials via GPO (CachedLogonsCount).",
    "network.cisco_type5": "Upgrade to Type 8 or Type 9 passwords. Type 5 (md5crypt) is considered weak.",
    "network.cisco_type8": "Ensure IOS-XE is current. Type 8 is acceptable but Type 9 is preferred.",
    "network.cisco_type9": "Type 9 (scrypt) is the strongest option. Ensure it's used for all secrets.",
    "token.ansible_vault": "Use strong vault passwords (≥20 random chars). Rotate vault passwords regularly.",
}


def generate_report(results: list[CrackResult], config: ReportConfig | None = None) -> str:
    """Generate a professional pentest-quality markdown report.

    Args:
        results: List of CrackResult objects
        config: Report configuration

    Returns:
        Complete markdown report as string
    """
    if config is None:
        config = ReportConfig()

    if not config.date:
        config.date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections: list[str] = []

    # ── Header ────────────────────────────────────────────────────────
    sections.append(f"# {config.title}")
    sections.append(f"**Classification:** {config.classification}")
    sections.append(f"**Date:** {config.date}")
    sections.append(f"**Assessor:** {config.assessor}")
    sections.append(f"**Target:** {config.target}")
    sections.append("")

    # ── Executive Summary ─────────────────────────────────────────────
    total = len(results)
    cracked = sum(1 for r in results if r.cracked)
    unique_types = len(set(r.format_id for r in results))

    sections.append("## Executive Summary")
    sections.append(f"A total of **{total}** password hashes were analyzed across "
                    f"**{unique_types}** distinct hash types.")
    if cracked > 0:
        pct = (cracked / total * 100) if total > 0 else 0
        sections.append(f"**{cracked}/{total} ({pct:.0f}%)** passwords were successfully recovered.")
        sections.append("This indicates a significant risk of unauthorized access.")
    else:
        sections.append("No passwords were recovered during this assessment.")
    sections.append("")

    # ── Findings ──────────────────────────────────────────────────────
    sections.append("## Technical Findings")
    sections.append("")
    sections.append("| # | Hash Type | Hashcat Mode | Cracked | Attack Mode | Time |")
    sections.append("|---|-----------|:------------|:-------:|-------------|------|")

    for i, r in enumerate(results, 1):
        cracked_str = "✅ YES" if r.cracked else "❌ No"
        time_str = f"{r.time_taken:.1f}s" if r.time_taken > 0 else "N/A"
        hm = str(r.hashcat_mode) if r.hashcat_mode is not None else "—"
        sections.append(f"| {i} | {r.algorithm} | {hm} | {cracked_str} | {r.attack_mode or '—'} | {time_str} |")

    sections.append("")

    # ── Cracked Passwords ─────────────────────────────────────────────
    cracked_results = [r for r in results if r.cracked]
    if cracked_results:
        sections.append("## Recovered Credentials")
        sections.append("| Hash Type | Password | Complexity |")
        sections.append("|-----------|----------|-----------|")
        for r in cracked_results:
            complexity = _password_complexity(r.password)
            sections.append(f"| {r.algorithm} | `{r.password}` | {complexity} |")
        sections.append("")

    # ── MITRE ATT&CK ──────────────────────────────────────────────────
    if config.include_mitre:
        format_ids = list(set(r.format_id for r in results))
        mitre_found = False
        for fid in format_ids:
            mappings = get_mitre_mappings(fid)
            if mappings:
                if not mitre_found:
                    sections.append("## MITRE ATT&CK Mapping")
                    mitre_found = True
                for m in mappings:
                    sections.append(f"- **{m.technique_id}** — {m.technique_name} ({m.tactic})")
        if mitre_found:
            sections.append("")

    # ── Remediation ───────────────────────────────────────────────────
    if config.include_remediation:
        sections.append("## Remediation Recommendations")
        for fid in sorted(set(r.format_id for r in results)):
            remediation = _REMEDIATION.get(fid)
            if remediation:
                sections.append(f"### {fid}")
                sections.append(remediation)
                sections.append("")

    return "\n".join(sections)


def _password_complexity(password: str) -> str:
    """Assess password complexity."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = sum([has_upper, has_lower, has_digit, has_special])

    if length < 6:
        return "🔴 Very Weak"
    if length < 8 or score <= 1:
        return "🟠 Weak"
    if length < 12 or score <= 2:
        return "🟡 Fair"
    if length < 16 or score <= 3:
        return "🟢 Good"
    return "🟢 Strong"
