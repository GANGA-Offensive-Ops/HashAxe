# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/core/hash_registry.py
#  Central Hash Type Registry — Single Source of Truth for all hash metadata.
#  Eliminates fragmentation across HASHCAT_MODES, _HASHCAT_MODES, and _BENCHMARKS.
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
hashaxe.core.hash_registry — Central Hash Type Registry.

Single source of truth for all hash-related metadata:
  • Hashcat mode numbers
  • John the Ripper format strings
  • Difficulty classification
  • GPU benchmark data (hashes/sec by hardware tier)
  • Category classification

All other modules (classifier, estimator, fast_hash_cracker) derive
their lookup dicts from this registry. Adding a new hash type = one entry here.

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class HashType:
    """Immutable descriptor for a single hash type."""
    format_id: str                          # Canonical dotted ID (e.g. "hash.md5")
    canonical_name: str                     # Human-readable (e.g. "MD5")
    hashcat_mode: int | None = None         # hashcat -m value, None if unsupported
    john_format: str | None = None          # John --format string
    difficulty: str = "MEDIUM"              # TRIVIAL / FAST / MEDIUM / SLOW / EXTREME
    category: str = "hash"                  # hash / network / token / archive / document / ssh / pwm / disk
    gpu_supported: bool = False             # True if hashcat can hashaxe this format
    benchmarks: dict[str, float] = field(default_factory=dict)  # {cpu, gpu_mid, gpu_high} → H/s


# ══════════════════════════════════════════════════════════════════════════════
# THE REGISTRY — Single Source of Truth
# ══════════════════════════════════════════════════════════════════════════════

HASH_REGISTRY: dict[str, HashType] = {}

def _r(ht: HashType) -> None:
    """Register a HashType in the global registry."""
    HASH_REGISTRY[ht.format_id] = ht


# ── Raw Hash Digests ──────────────────────────────────────────────────────────

_r(HashType(
    format_id="hash.md5", canonical_name="MD5",
    hashcat_mode=0, john_format="Raw-MD5",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e8, "gpu_mid": 2e10, "gpu_high": 6.5e10},
))
_r(HashType(
    format_id="hash.sha1", canonical_name="SHA-1",
    hashcat_mode=100, john_format="Raw-SHA1",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 2e8, "gpu_mid": 1e10, "gpu_high": 3.5e10},
))
_r(HashType(
    format_id="hash.sha224", canonical_name="SHA-224",
    hashcat_mode=1300, john_format="Raw-SHA224",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1.5e8, "gpu_mid": 5e9, "gpu_high": 1.8e10},
))
_r(HashType(
    format_id="hash.sha256", canonical_name="SHA-256",
    hashcat_mode=1400, john_format="Raw-SHA256",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e8, "gpu_mid": 4e9, "gpu_high": 1.5e10},
))
_r(HashType(
    format_id="hash.sha384", canonical_name="SHA-384",
    hashcat_mode=10800, john_format="Raw-SHA384",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 7e7, "gpu_mid": 2e9, "gpu_high": 8e9},
))
_r(HashType(
    format_id="hash.sha512", canonical_name="SHA-512",
    hashcat_mode=1700, john_format="Raw-SHA512",
    difficulty="FAST", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e7, "gpu_mid": 1.5e9, "gpu_high": 5e9},
))
_r(HashType(
    format_id="hash.ntlm", canonical_name="NTLM",
    hashcat_mode=1000, john_format="NT",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e8, "gpu_mid": 2e10, "gpu_high": 7e10},
))
_r(HashType(
    format_id="hash.lm", canonical_name="LM",
    hashcat_mode=3000, john_format="LM",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 3e8, "gpu_mid": 1e10, "gpu_high": 5e10},
))

# ── Unix Crypt Family ─────────────────────────────────────────────────────────

_r(HashType(
    format_id="hash.descrypt", canonical_name="DES crypt",
    hashcat_mode=1500, john_format="descrypt",
    difficulty="FAST", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e7, "gpu_mid": 5e9, "gpu_high": 2e10},
))
_r(HashType(
    format_id="hash.md5crypt", canonical_name="md5crypt $1$",
    hashcat_mode=500, john_format="md5crypt",
    difficulty="FAST", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e5, "gpu_mid": 2e7, "gpu_high": 7e7},
))
_r(HashType(
    format_id="hash.sha256crypt", canonical_name="sha256crypt $5$",
    hashcat_mode=7400, john_format="sha256crypt",
    difficulty="MEDIUM", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e4, "gpu_mid": 5e6, "gpu_high": 1.5e7},
))
_r(HashType(
    format_id="hash.sha512crypt", canonical_name="sha512crypt $6$",
    hashcat_mode=1800, john_format="sha512crypt",
    difficulty="MEDIUM", category="hash", gpu_supported=True,
    benchmarks={"cpu": 2e4, "gpu_mid": 1e6, "gpu_high": 5e6},
))

# ── Modern KDFs ───────────────────────────────────────────────────────────────

_r(HashType(
    format_id="hash.bcrypt", canonical_name="bcrypt",
    hashcat_mode=3200, john_format="bcrypt",
    difficulty="SLOW", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e2, "gpu_mid": 3e4, "gpu_high": 1e5},
))
_r(HashType(
    format_id="hash.scrypt", canonical_name="scrypt",
    hashcat_mode=8900, john_format="scrypt",
    difficulty="EXTREME", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e1, "gpu_mid": 1e3, "gpu_high": 5e3},
))
_r(HashType(
    format_id="hash.argon2", canonical_name="Argon2",
    hashcat_mode=34000, john_format="argon2",
    difficulty="EXTREME", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e1, "gpu_mid": 5e2, "gpu_high": 2e3},
))

# ── Database ──────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="hash.mysql", canonical_name="MySQL native_password",
    hashcat_mode=300, john_format="mysql-sha1",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e9, "gpu_mid": 1e10, "gpu_high": 4e10},
))
_r(HashType(
    format_id="hash.postgres", canonical_name="PostgreSQL MD5",
    hashcat_mode=12, john_format="postgres",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 5e8, "gpu_mid": 5e9, "gpu_high": 2e10},
))
_r(HashType(
    format_id="hash.mssql2005", canonical_name="MSSQL 2005+",
    hashcat_mode=132, john_format="mssql05",
    difficulty="TRIVIAL", category="hash", gpu_supported=True,
    benchmarks={"cpu": 3e8, "gpu_mid": 5e9, "gpu_high": 2e10},
))
_r(HashType(
    format_id="hash.mssql2012", canonical_name="MSSQL 2012+",
    hashcat_mode=1731, john_format="mssql12",
    difficulty="FAST", category="hash", gpu_supported=True,
    benchmarks={"cpu": 1e8, "gpu_mid": 2e9, "gpu_high": 8e9},
))

# ── Network Authentication ───────────────────────────────────────────────────

_r(HashType(
    format_id="network.ntlmv1", canonical_name="NetNTLMv1",
    hashcat_mode=5500, john_format="netntlm",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e7, "gpu_mid": 5e9, "gpu_high": 2e10},
))
_r(HashType(
    format_id="network.ntlmv2", canonical_name="NetNTLMv2",
    hashcat_mode=5600, john_format="netntlmv2",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 1e7, "gpu_mid": 3e9, "gpu_high": 1e10},
))

# ── Kerberos ──────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="network.krb5tgs_rc4", canonical_name="Kerberoast TGS RC4",
    hashcat_mode=13100, john_format="krb5tgs",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e6, "gpu_mid": 1e9, "gpu_high": 3e9},
))
_r(HashType(
    format_id="network.krb5asrep_rc4", canonical_name="AS-REP Roast RC4",
    hashcat_mode=18200, john_format="krb5asrep",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e6, "gpu_mid": 1e9, "gpu_high": 3e9},
))
_r(HashType(
    format_id="network.krb5tgs_aes128", canonical_name="Kerberos TGS AES128",
    hashcat_mode=19600, john_format="krb5tgs-aes128",
    difficulty="MEDIUM", category="network", gpu_supported=True,
    benchmarks={"cpu": 1e5, "gpu_mid": 1e7, "gpu_high": 5e7},
))
_r(HashType(
    format_id="network.krb5tgs_aes256", canonical_name="Kerberos TGS AES256",
    hashcat_mode=19700, john_format="krb5tgs-aes256",
    difficulty="MEDIUM", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e4, "gpu_mid": 5e6, "gpu_high": 2e7},
))

# ── Domain Cached Credentials ────────────────────────────────────────────────

_r(HashType(
    format_id="network.dcc1", canonical_name="DCC MS Cache v1",
    hashcat_mode=1100, john_format="DCC",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 1e8, "gpu_mid": 5e9, "gpu_high": 2e10},
))
_r(HashType(
    format_id="network.dcc2", canonical_name="DCC2 MS Cache v2",
    hashcat_mode=2100, john_format="DCC2",
    difficulty="SLOW", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))

# ── Cisco ─────────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="network.cisco_type5", canonical_name="Cisco Type 5 (md5crypt)",
    hashcat_mode=500, john_format="md5crypt",
    difficulty="FAST", category="network", gpu_supported=True,
    benchmarks={"cpu": 1e5, "gpu_mid": 2e7, "gpu_high": 7e7},
))
_r(HashType(
    format_id="network.cisco_type8", canonical_name="Cisco Type 8 (PBKDF2)",
    hashcat_mode=9200, john_format="cisco8",
    difficulty="SLOW", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))
_r(HashType(
    format_id="network.cisco_type9", canonical_name="Cisco Type 9 (scrypt)",
    hashcat_mode=9300, john_format="cisco9",
    difficulty="EXTREME", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e1, "gpu_mid": 1e3, "gpu_high": 5e3},
))

# ── DPAPI ─────────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="disk.dpapi", canonical_name="DPAPI Masterkey",
    hashcat_mode=15300, john_format="dpapimk",
    difficulty="SLOW", category="disk", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))

# ── Tokens ────────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="hash.jwt", canonical_name="JWT (HMAC)",
    hashcat_mode=16500, john_format="HMAC-SHA256",
    difficulty="FAST", category="token", gpu_supported=True,
    benchmarks={"cpu": 1e7, "gpu_mid": 5e8, "gpu_high": 2e9},
))
_r(HashType(
    format_id="token.ansible_vault", canonical_name="Ansible Vault (AES-256)",
    hashcat_mode=16900, john_format="ansible",
    difficulty="SLOW", category="token", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))

# ── Archives ──────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="archive.7z", canonical_name="7-Zip",
    hashcat_mode=11600, john_format="7z",
    difficulty="SLOW", category="archive", gpu_supported=True,
    benchmarks={"cpu": 1e3, "gpu_mid": 1e5, "gpu_high": 5e5},
))
_r(HashType(
    format_id="archive.rar", canonical_name="RAR",
    hashcat_mode=13000, john_format="rar",
    difficulty="SLOW", category="archive", gpu_supported=True,
    benchmarks={"cpu": 1e3, "gpu_mid": 1e5, "gpu_high": 5e5},
))
_r(HashType(
    format_id="archive.zip", canonical_name="ZIP",
    hashcat_mode=13600, john_format="zip",
    difficulty="MEDIUM", category="archive", gpu_supported=True,
    benchmarks={"cpu": 5e4, "gpu_mid": 5e6, "gpu_high": 2e7},
))

# ── Documents ─────────────────────────────────────────────────────────────────

_r(HashType(
    format_id="document.pdf", canonical_name="PDF",
    hashcat_mode=10500, john_format="pdf",
    difficulty="MEDIUM", category="document", gpu_supported=True,
    benchmarks={"cpu": 5e4, "gpu_mid": 5e6, "gpu_high": 2e7},
))

# ── Password Managers ─────────────────────────────────────────────────────────

_r(HashType(
    format_id="pwm.keepass", canonical_name="KeePass KDBX",
    hashcat_mode=13400, john_format="KeePass",
    difficulty="SLOW", category="pwm", gpu_supported=True,
    benchmarks={"cpu": 1e3, "gpu_mid": 1e5, "gpu_high": 5e5},
))
_r(HashType(
    format_id="pwm.office", canonical_name="Microsoft Office",
    hashcat_mode=9600, john_format="office",
    difficulty="MEDIUM", category="pwm", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))

# ── SSH Keys (CPU-only — no hashcat mode) ─────────────────────────────────────

_r(HashType(
    format_id="ssh.openssh", canonical_name="OpenSSH Private Key",
    hashcat_mode=22921, john_format="ssh",
    difficulty="MEDIUM", category="ssh", gpu_supported=True,
    benchmarks={"cpu": 5e3, "gpu_mid": 5e5, "gpu_high": 2e6},
))
_r(HashType(
    format_id="ssh.ppk", canonical_name="PuTTY PPK",
    hashcat_mode=None, john_format="putty",
    difficulty="EXTREME", category="ssh", gpu_supported=False,
    benchmarks={"cpu": 1e1, "gpu_mid": 1e1, "gpu_high": 1e1},
))

# ── Network Captures ──────────────────────────────────────────────────────────

_r(HashType(
    format_id="network.wpa", canonical_name="WPA/WPA2",
    hashcat_mode=22000, john_format="wpapsk",
    difficulty="SLOW", category="network", gpu_supported=True,
    benchmarks={"cpu": 5e2, "gpu_mid": 5e4, "gpu_high": 2e5},
))


# ══════════════════════════════════════════════════════════════════════════════
# ACCESSOR FUNCTIONS — Used by consumer modules
# ══════════════════════════════════════════════════════════════════════════════

def get_hashcat_mode(format_id: str) -> int | None:
    """Return hashcat -m mode for a format, or None if not supported."""
    ht = HASH_REGISTRY.get(format_id)
    return ht.hashcat_mode if ht else None


def get_john_format(format_id: str) -> str | None:
    """Return John the Ripper --format string for a format."""
    ht = HASH_REGISTRY.get(format_id)
    return ht.john_format if ht else None


def get_difficulty(format_id: str) -> str:
    """Return difficulty classification for a format."""
    ht = HASH_REGISTRY.get(format_id)
    return ht.difficulty if ht else "unknown"


def get_benchmarks(format_id: str) -> dict[str, float]:
    """Return benchmark dict for a format."""
    ht = HASH_REGISTRY.get(format_id)
    return dict(ht.benchmarks) if ht else {}


def is_gpu_supported(format_id: str) -> bool:
    """Return True if hashcat can hashaxe this format."""
    ht = HASH_REGISTRY.get(format_id)
    return ht.gpu_supported if ht else False


def get_all_hashcat_modes() -> dict[str, int]:
    """Return a dict of format_id → hashcat mode for all GPU-supported formats."""
    return {
        ht.format_id: ht.hashcat_mode
        for ht in HASH_REGISTRY.values()
        if ht.hashcat_mode is not None and ht.gpu_supported
    }


def get_all_difficulties() -> dict[str, str]:
    """Return a dict of format_id → difficulty for all registered formats."""
    return {ht.format_id: ht.difficulty for ht in HASH_REGISTRY.values()}


def get_all_benchmarks() -> dict[str, dict[str, float]]:
    """Return a dict of format_id → benchmark dict for all registered formats."""
    return {
        ht.format_id: dict(ht.benchmarks)
        for ht in HASH_REGISTRY.values()
        if ht.benchmarks
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

def registry_stats() -> dict[str, int]:
    """Return summary statistics about the registry."""
    total = len(HASH_REGISTRY)
    gpu = sum(1 for ht in HASH_REGISTRY.values() if ht.gpu_supported)
    categories = len(set(ht.category for ht in HASH_REGISTRY.values()))
    return {
        "total_formats": total,
        "gpu_supported": gpu,
        "cpu_only": total - gpu,
        "categories": categories,
    }
