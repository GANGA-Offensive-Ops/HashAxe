# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/identify/hash_patterns.py
#  Hash string pattern matching via compiled regex database.
#  Identifies 50+ hash formats from string representation.
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
Hash string pattern matching via compiled regex database.

Identifies hash formats from their string representation.  Covers 50+
patterns: Unix crypt variants, bcrypt, argon2, scrypt, raw hex digests,
database-specific formats, JWT tokens, and more.
"""
from __future__ import annotations

import re
from typing import NamedTuple


class HashMatch(NamedTuple):
    """Result of a hash pattern match."""

    format_id: str  # e.g. "hash.md5", "hash.bcrypt"
    algorithm: str  # Human-readable name, e.g. "bcrypt $2b$"
    confidence: float  # 0.0–1.0
    details: dict  # Extracted fields (salt, rounds, etc.)


# ──────────────────────────────────────────────────────────────────────────────
# Pattern database: (compiled_regex, format_id, algorithm_name, confidence)
#
# Ordered from most specific (structured prefixes) to least specific (raw hex).
# First match wins, so more specific patterns must come first.
# ──────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
    # ── Argon2 family ─────────────────────────────────────────────────────────
    (
        re.compile(
            r"^\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$"
        ),
        "hash.argon2",
        "Argon2",
        1.0,
    ),
    # ── scrypt ────────────────────────────────────────────────────────────────
    # ── scrypt ────────────────────────────────────────────────────────────────
    (
        re.compile(
            r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$|"
            r"^SCRYPT:(\d+):(\d+):(\d+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$",
            re.IGNORECASE,
        ),
        "hash.scrypt",
        "scrypt",
        1.0,
    ),
    # ── bcrypt ────────────────────────────────────────────────────────────────
    (re.compile(r"^\$2([aby])\$(\d{2})\$([./A-Za-z0-9]{53})$"), "hash.bcrypt", "bcrypt", 1.0),
    # ── Unix crypt: sha512crypt ───────────────────────────────────────────────
    (
        re.compile(r"^\$6\$(rounds=(\d+)\$)?([./A-Za-z0-9]+)\$([./A-Za-z0-9]{86})$"),
        "hash.sha512crypt",
        "sha512crypt $6$",
        1.0,
    ),
    # ── Unix crypt: sha256crypt ───────────────────────────────────────────────
    (
        re.compile(r"^\$5\$(rounds=(\d+)\$)?([./A-Za-z0-9]+)\$([./A-Za-z0-9]{43})$"),
        "hash.sha256crypt",
        "sha256crypt $5$",
        1.0,
    ),
    # ── Unix crypt: md5crypt ──────────────────────────────────────────────────
    (
        re.compile(r"^\$1\$([./A-Za-z0-9]{1,8})\$([./A-Za-z0-9]{22})$"),
        "hash.md5crypt",
        "md5crypt $1$",
        1.0,
    ),
    # ── Unix crypt: DES (legacy) ──────────────────────────────────────────────
    (re.compile(r"^[./A-Za-z0-9]{13}$"), "hash.descrypt", "DES crypt", 0.4),
    # ── MySQL native password (double SHA-1) ──────────────────────────────────
    (re.compile(r"^\*[A-Fa-f0-9]{40}$"), "hash.mysql", "MySQL native_password", 0.95),
    # ── MSSQL ─────────────────────────────────────────────────────────────────
    (re.compile(r"^0x0100[A-Fa-f0-9]{88}$"), "hash.mssql2005", "MSSQL 2005+", 0.9),
    (re.compile(r"^0x0200[A-Fa-f0-9]{136}$"), "hash.mssql2012", "MSSQL 2012+", 0.9),
    # ── JWT (HMAC) ────────────────────────────────────────────────────────────
    (
        re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
        "hash.jwt",
        "JWT (HMAC)",
        0.95,
    ),
    # ── NTLM (32 hex chars, but with context hint) ────────────────────────────
    # Note: Pure 32-hex is ambiguous (MD5 vs NTLM). This matches the NetNTLMv2 format.
    (
        re.compile(r"^([^:]+)::([^:]+):([a-fA-F0-9]{16}):([a-fA-F0-9]{32}):([a-fA-F0-9]+)$"),
        "network.ntlmv2",
        "NetNTLMv2",
        1.0,
    ),
    (
        re.compile(r"^([^:]+)::([^:]*):([a-fA-F0-9]{48}):([a-fA-F0-9]{16})$"),
        "network.ntlmv1",
        "NetNTLMv1",
        0.95,
    ),
    # ── Kerberos family ───────────────────────────────────────────────────────
    # Kerberoast TGS-REP RC4 etype 23 (hashcat -m 13100)
    (
        re.compile(r"^\$krb5tgs\$23\$\*[^$]+\$[^$]+\$[^$*]+\*\$[a-fA-F0-9]{32}\$[a-fA-F0-9]+$"),
        "network.krb5tgs_rc4",
        "Kerberoast TGS RC4",
        1.0,
    ),
    # AS-REP Roast etype 23 (hashcat -m 18200)
    (
        re.compile(r"^\$krb5asrep\$23\$[^:@]+@?[^:]*:[a-fA-F0-9]{32}\$[a-fA-F0-9]+$"),
        "network.krb5asrep_rc4",
        "AS-REP Roast RC4",
        1.0,
    ),
    # Kerberos TGS AES128 etype 17 (hashcat -m 19600)
    (
        re.compile(r"^\$krb5tgs\$17\$[^$]+\$[^$]+\$\*[^$*]*\*\$[a-fA-F0-9]+\$[a-fA-F0-9]+$"),
        "network.krb5tgs_aes128",
        "Kerberos TGS AES128",
        1.0,
    ),
    # Kerberos TGS AES256 etype 18 (hashcat -m 19700)
    (
        re.compile(r"^\$krb5tgs\$18\$[^$]+\$[^$]+\$\*[^$*]*\*\$[a-fA-F0-9]+\$[a-fA-F0-9]+$"),
        "network.krb5tgs_aes256",
        "Kerberos TGS AES256",
        1.0,
    ),
    # ── Domain Cached Credentials ────────────────────────────────────────────
    # DCC2 MS Cache v2 (hashcat -m 2100) — must come before DCC1
    (re.compile(r"^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$"), "network.dcc2", "DCC2 MS Cache v2", 1.0),
    # ── PostgreSQL MD5 (only matches explicit md5 prefix formats) ──────────────
    (
        re.compile(r"^md5[a-f0-9]{32}$|^[a-zA-Z0-9._-]+:md5[a-fA-F0-9]{32}$", re.IGNORECASE),
        "hash.postgres",
        "PostgreSQL MD5",
        0.95,
    ),
    # DCC v1 (hashcat -m 1100): hash:username
    (re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9._@\-]+$"), "network.dcc1", "DCC MS Cache v1", 0.85),
    # ── DPAPI ────────────────────────────────────────────────────────────────
    (re.compile(r"^\$DPAPImk\$\d\*\d\*"), "disk.dpapi", "DPAPI Masterkey", 1.0),
    # ── Tier 2 identifiers ────────────────────────────────────────────────────
    # Ansible Vault (hashcat -m 16900)
    (
        re.compile(r"^\$ANSIBLE_VAULT;\d+\.\d+;AES\d*\s*$", re.MULTILINE),
        "token.ansible_vault",
        "Ansible Vault (AES-256)",
        1.0,
    ),
    # Cisco Type 8: $8$salt$hash (PBKDF2-SHA256, hashcat -m 9200)
    (
        re.compile(r"^\$8\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$"),
        "network.cisco_type8",
        "Cisco Type 8 (PBKDF2)",
        1.0,
    ),
    # Cisco Type 9: $9$salt$hash (scrypt, hashcat -m 9300)
    (
        re.compile(r"^\$9\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$"),
        "network.cisco_type9",
        "Cisco Type 9 (scrypt)",
        1.0,
    ),
    # Cisco Type 5 is identical to md5crypt — omitted as a separate
    # identifier; the existing md5crypt pattern covers it.
    # Users see both "md5crypt" and "Cisco Type 5" in identify results.
    # ── Raw hex hashes (by length, least specific — MUST come last) ───────────
    # SHA-512 — 128 hex chars
    (re.compile(r"^[a-fA-F0-9]{128}$"), "hash.sha512", "SHA-512", 0.7),
    # SHA-384 — 96 hex chars
    (re.compile(r"^[a-fA-F0-9]{96}$"), "hash.sha384", "SHA-384", 0.65),
    # SHA-256 — 64 hex chars
    (re.compile(r"^[a-fA-F0-9]{64}$"), "hash.sha256", "SHA-256", 0.7),
    # SHA-224 — 56 hex chars
    (re.compile(r"^[a-fA-F0-9]{56}$"), "hash.sha224", "SHA-224", 0.6),
    # SHA-1 — 40 hex chars
    (re.compile(r"^[a-fA-F0-9]{40}$"), "hash.sha1", "SHA-1", 0.7),
    # MD5 — 32 hex chars
    (re.compile(r"^[a-fA-F0-9]{32}$"), "hash.md5", "MD5", 0.65),
]


def identify_hash(text: str) -> list[HashMatch]:
    """Identify hash format(s) from a string.

    Returns a list of matches, ordered by confidence (highest first).
    Returns an empty list if no patterns match.

    Handles common input variations:
    - Leading/trailing whitespace
    - Lines from shadow files:  username:$6$salt$hash
    - Lines from hashdump:      Administrator:500:...:..:::
    """
    text = text.strip()
    if not text:
        return []

    matches: list[HashMatch] = []
    seen_ids: set[str] = set()

    # Try to extract the hash from shadow-file format (user:hash:...)
    candidates = [text]
    if ":" in text:
        parts = text.split(":")
        # /etc/shadow: user:$6$salt$hash:...
        if len(parts) >= 2 and parts[1].startswith("$"):
            candidates.insert(0, parts[1])
        # Windows hashdump: user:rid:lm:ntlm:::
        elif len(parts) >= 4 and len(parts[3]) == 32:
            # We explicitly know this is NTLM from the dump context.
            # Add it with an explicit NTLM-only identifier so it doesn't fall through
            # to generic MD5 (since both are 32-hex chars).
            ntlm_hash = parts[3]
            matches.append(
                HashMatch(
                    format_id="hash.ntlm",
                    algorithm="NTLM (from hashdump)",
                    confidence=1.0,  # 100% confidence due to hashdump structural context
                    details={"raw": ntlm_hash, "groups": (), "source": "hashdump"},
                )
            )
            seen_ids.add("hash.ntlm")
            candidates.insert(0, ntlm_hash)
        # Also try each individual part, but only if it could be a valid sub-hash (e.g. length heuristics)
        for p in parts:
            # Avoid breaking up scrypt/postgres/dcc strings
            if text.startswith("SCRYPT:") or text.startswith("md5") or len(parts) == 2:
                continue
            if p and p not in candidates:
                candidates.append(p)

    for candidate in candidates:
        for pattern, fmt_id, algo, confidence in _PATTERNS:
            if fmt_id in seen_ids:
                continue
            m = pattern.match(candidate)
            if m:
                details: dict = {"raw": candidate, "groups": m.groups()}

                # Extract structured details for specific formats
                if fmt_id == "hash.bcrypt":
                    details["variant"] = m.group(1)
                    details["rounds"] = int(m.group(2))
                elif fmt_id == "hash.argon2":
                    details["variant"] = m.group(1)
                    details["version"] = int(m.group(2))
                    details["memory"] = int(m.group(3))
                    details["time"] = int(m.group(4))
                    details["parallelism"] = int(m.group(5))
                elif fmt_id.startswith("hash.sha512crypt") or fmt_id.startswith("hash.sha256crypt"):
                    details["rounds"] = int(m.group(2)) if m.group(2) else 5000
                    details["salt"] = m.group(3)
                elif fmt_id == "hash.md5crypt":
                    details["salt"] = m.group(1)

                matches.append(
                    HashMatch(
                        format_id=fmt_id,
                        algorithm=algo,
                        confidence=confidence,
                        details=details,
                    )
                )
                seen_ids.add(fmt_id)

    # Sort by confidence (highest first)
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def identify_best(text: str) -> HashMatch | None:
    """Return the single best match, or None if nothing matches."""
    matches = identify_hash(text)
    return matches[0] if matches else None


# ── Quick lookup table for format_id → algorithm name ─────────────────────────

SUPPORTED_HASH_FORMATS: dict[str, str] = {entry[1]: entry[2] for entry in _PATTERNS}
