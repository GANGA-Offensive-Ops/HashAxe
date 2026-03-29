#!/bin/bash

# =============================================================================
# Hashaxe V1 - HYBRID ATTACKS Test Suite
# =============================================================================
# Description: Tests all hybrid attack commands combining wordlist with mask
#              append/prepend patterns across all supported hash types.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_6_hybrid_attacks.sh
#   ./file_6_hybrid_attacks.sh --resume 20
#   ./file_6_hybrid_attacks.sh --dry-run
#   ./file_6_hybrid_attacks.sh --timeout 180
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="HYBRID ATTACKS"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (JWT, Cisco 5, Kerberos, NetNTLM, SSH keys) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, descrypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
#
# Hybrid attack patterns:
#   --mask '?d' = append 4 digits to wordlist
#   --mask '?d?d'     = append 2 digits to wordlist
#   --mask '?s'       = append special char to wordlist
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH OpenSSH Key (password: xr7kQ2m123) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d':::SSH OpenSSH Key — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::SSH OpenSSH Key — hybrid 2d:::180"

    # ── SSH PPK Key (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --mask '?d':::SSH PPK Key — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::SSH PPK Key — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # FAST HASHES (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL, MSSQL)
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 Hash (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MD5 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::MD5 Hash — hybrid 2d:::60"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MD5 Hash (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MD5 Hash (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MD5 Hash (double-quoted) — hybrid 1d:::60"

    # ── SHA-1 Hash (password: password) ──────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-1 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::SHA-1 Hash — hybrid 2d:::60"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-1 Hash (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-1 Hash (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-1 Hash (double-quoted) — hybrid 1d:::60"

    # ── SHA-224 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-224 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::SHA-224 Hash — hybrid 2d:::60"

    # ── SHA-256 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-256 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::SHA-256 Hash — hybrid 2d:::60"

    # ── SHA-384 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-384 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::SHA-384 Hash — hybrid 2d:::60"

    # ── SHA-512 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::SHA-512 Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::SHA-512 Hash — hybrid 2d:::60"

    # ── NTLM Hash (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NTLM Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::NTLM Hash — hybrid 2d:::60"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NTLM Hash (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NTLM Hash (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NTLM Hash (double-quoted) — hybrid 1d:::60"

    # ── LM Hash (password: PASSWORD) ──────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?u':::LM Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?u?u':::LM Hash — hybrid 2d:::60"

    # ── MySQL Native Password (password: password) ────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MySQL Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::MySQL Hash — hybrid 2d:::60"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MySQL Hash (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MySQL Hash (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MySQL Hash (double-quoted) — hybrid 1d:::60"

    # ── PostgreSQL MD5 (password: password) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash hashcat — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::PostgreSQL Hash hashcat — hybrid 2d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash john — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::PostgreSQL Hash john — hybrid 2d:::60"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash john format (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash john format (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash john format (double-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash hashcat format (inline) — hybrid 1d:::60"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash hashcat format (single-quoted) — hybrid 1d:::60"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" -w ${TEST_FILES_DIR}/password.txt --mask '?l':::PostgreSQL Hash hashcat format (double-quoted) — hybrid 1d:::60"

    # ── MSSQL 2012+ (password: password) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::MSSQL Hash — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::MSSQL Hash — hybrid 2d:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # SLOW HASHES (bcrypt-4, md5crypt, descrypt)
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt Cost 4 (password: xr7kQ2m123) ───────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::bcrypt cost-4 — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::bcrypt cost-4 — hybrid 2d:::120"

    # ── md5crypt (password: xr7kQ2m123) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::md5crypt — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::md5crypt — hybrid 2d:::120"

    # ── DES Crypt (password: hashcat) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::descrypt — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::descrypt — hybrid 2d:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # VERY SLOW HASHES (bcrypt-10, Argon2id, scrypt, sha-crypt)
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt Cost 10 (password: Shadow@HTB2026) ─────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::bcrypt cost-10 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::bcrypt cost-10 — hybrid 2d:::180"

    # ── Argon2id (password: Shadow@HTB2026) ───────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::Argon2id — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::Argon2id — hybrid 2d:::180"

    # ── scrypt (password: Shadow@HTB2026) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::scrypt — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::scrypt — hybrid 2d:::180"

    # ── sha256crypt (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::sha256crypt — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::sha256crypt — hybrid 2d:::180"

    # ── sha512crypt (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::sha512crypt — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::sha512crypt — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # JWT (Medium)
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT HS256 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::JWT HS256 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::JWT HS256 — hybrid 2d:::180"

    # ── JWT HS384 (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::JWT HS384 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::JWT HS384 — hybrid 2d:::180"

    # ── JWT HS512 (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::JWT HS512 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::JWT HS512 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # NETWORK / INFRA
    # ═════════════════════════════════════════════════════════════════════════

    # ── Ansible Vault (password: Shadow@HTB2026) ──────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::Ansible Vault — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::Ansible Vault — hybrid 2d:::180"

    # ── Cisco Type 5 (password: xr7kQ2m123) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::Cisco Type 5 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::Cisco Type 5 — hybrid 2d:::180"

    # ── Cisco Type 8 (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::Cisco Type 8 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::Cisco Type 8 — hybrid 2d:::180"

    # ── Cisco Type 9 (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::Cisco Type 9 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::Cisco Type 9 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberoast TGS-REP RC4 (password: password) ──────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::Kerberos TGS-RC4 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::Kerberos TGS-RC4 — hybrid 2d:::180"

    # ── AS-REP Roast RC4 (password: password) ─────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::Kerberos AS-REP-RC4 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::Kerberos AS-REP-RC4 — hybrid 2d:::180"

    # ── Kerberos TGS AES128 (password: Shadow@HTB2026) ────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::Kerberos TGS-AES128 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::Kerberos TGS-AES128 — hybrid 2d:::180"

    # ── Kerberos TGS AES256 (password: Shadow@HTB2026) ────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::Kerberos TGS-AES256 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::Kerberos TGS-AES256 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NetNTLMv1 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::NetNTLMv1 — hybrid 2d:::180"

    # ── NetNTLMv2 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::NetNTLMv2 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::NetNTLMv2 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DCC (Domain Cached Credentials)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC v1 (password: password) ───────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l':::DCC v1 — hybrid 1d:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?l?l':::DCC v1 — hybrid 2d:::60"

    # ── DCC v2 (password: Shadow@HTB2026) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::DCC v2 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::DCC v2 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 (password: Shadow@HTB2026) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::DPAPI v1 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::DPAPI v1 — hybrid 2d:::180"

    # ── DPAPI v2 (password: Shadow@HTB2026) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::DPAPI v2 — hybrid 1d:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::DPAPI v2 — hybrid 2d:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP Archive (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --mask '?d':::ZIP Archive — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::ZIP Archive — hybrid 2d:::120"
    # ── 7-Zip Archive (password: Shadow@HTB2026) ──────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --mask '?d':::7-Zip Archive — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::7-Zip Archive — hybrid 2d:::120"

    # ── RAR Archive (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --mask '?d':::RAR Archive — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::RAR Archive — hybrid 2d:::120"

    # ── PDF Document (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --mask '?d':::PDF Document — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::PDF Document — hybrid 2d:::120"

    # ── ODF Document (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --mask '?d':::ODT Document — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::ODT Document — hybrid 2d:::120"

    # ── Office DOCX (password: Shadow@HTB2026) ─────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --mask '?d':::Office DOCX — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::Office DOCX — hybrid 2d:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGERS
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass Database (password: Shadow@HTB2026) ───────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --mask '?d':::KeePass Database — hybrid 1d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --mask '?d?d':::KeePass Database — hybrid 2d:::120"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
