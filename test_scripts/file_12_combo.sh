#!/bin/bash

# =============================================================================
# Hashaxe V1 - COMBINATOR ATTACKS Test Suite
# =============================================================================
# Description: Tests all combinator attack commands combining two wordlists
#              for Cartesian product candidate generation.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_13_combo.sh
#   ./file_13_combo.sh --resume 20
#   ./file_13_combo.sh --dry-run
#   ./file_13_combo.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="COMBINATOR ATTACKS"
DEFAULT_TIMEOUT=60

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Combinator Attack mode:
#   --attack combinator  = Cartesian product of two wordlists
#   --wordlist2          = Second wordlist for combinator
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, JWT, Kerberos RC4, NetNTLM, Cisco 5) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── OpenSSH Keys ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::SSH OpenSSH Key — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::SSH OpenSSH Key — combinator GPU:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -v:::SSH OpenSSH Key — combinator verbose:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator --session combinator_attack_1:::SSH OpenSSH Key — combinator session:::60"

    # ── PuTTY PPK Keys ─────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::SSH PPK Key — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::SSH PPK Key — combinator GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASHES (Fast)
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 Hashes ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MD5 Hash (inline) — combinator password.txt:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MD5 Hash (single-quoted) — combinator password.txt:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MD5 Hash (double-quoted) — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MD5 Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::MD5 Hash — combinator GPU:::30"

    # ── SHA-1 Hashes ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::SHA-1 Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::SHA-1 Hash — combinator GPU:::30"

    # ── SHA-256 Hashes ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::SHA-256 Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::SHA-256 Hash — combinator GPU:::30"

    # ── SHA-512 Hashes ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::SHA-512 Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::SHA-512 Hash — combinator GPU:::30"

    # ── NTLM Hashes ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::NTLM Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::NTLM Hash — combinator GPU:::30"

    # ── LM Hashes ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::LM Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::LM Hash — combinator GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN HASHES (Slow/Very Slow)
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt cost-10 ─────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::bcrypt cost-10 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::bcrypt cost-10 — combinator 8 threads:::60"

    # ── Argon2id ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Argon2id — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::Argon2id — combinator 4 threads:::60"

    # ── scrypt ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::scrypt — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::scrypt — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT
    # ═════════════════════════════════════════════════════════════════════════

    # ── md5crypt ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::md5crypt — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::md5crypt — combinator GPU:::60"

    # ── sha256crypt ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::sha256crypt — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::sha256crypt — combinator 8 threads:::60"

    # ── sha512crypt ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::sha512crypt — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::sha512crypt — combinator 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── MySQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MySQL Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::MySQL Hash — combinator GPU:::30"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::PostgreSQL Hash hashcat — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::PostgreSQL Hash john — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::PostgreSQL Hash — combinator GPU:::30"

    # ── MSSQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::MSSQL Hash — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::MSSQL Hash — combinator GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # JWT & ANSIBLE
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT HS256 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::JWT HS256 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::JWT HS256 — combinator GPU:::60"

    # ── JWT HS384 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::JWT HS384 — combinator GPU:::60"

    # ── JWT HS512 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::JWT HS512 — combinator GPU:::60"

    # ── Ansible Vault ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Ansible Vault — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::Ansible Vault — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO TYPES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Cisco Type 5 ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Cisco Type 5 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::Cisco Type 5 — combinator GPU:::60"

    # ── Cisco Type 8 ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Cisco Type 8 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::Cisco Type 8 — combinator 8 threads:::60"

    # ── Cisco Type 9 ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Cisco Type 9 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::Cisco Type 9 — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberos TGS-RC4 ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Kerberos TGS-RC4 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::Kerberos TGS-RC4 — combinator GPU:::60"

    # ── Kerberos AS-REP-RC4 ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Kerberos AS-REP-RC4 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::Kerberos AS-REP-RC4 — combinator GPU:::60"

    # ── Kerberos TGS-AES128 ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::Kerberos TGS-AES128 — combinator 8 threads:::60"

    # ── Kerberos TGS-AES256 ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::Kerberos TGS-AES256 — combinator 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::NetNTLMv1 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::NetNTLMv1 — combinator GPU:::60"

    # ── NetNTLMv2 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::NetNTLMv2 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::NetNTLMv2 — combinator GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DCC & DPAPI
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC v1 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::DCC v1 — combinator password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator :::DCC v1 — combinator GPU:::30"

    # ── DCC v2 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::DCC v2 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::DCC v2 — combinator 8 threads:::60"

    # ── DPAPI v1 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::DPAPI v1 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::DPAPI v1 — combinator 8 threads:::60"

    # ── DPAPI v2 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::DPAPI v2 — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 8:::DPAPI v2 — combinator 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::WPA Handshake — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::WPA Handshake — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP Archive ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::ZIP Archive — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::ZIP Archive — combinator 4 threads:::60"

    # ── 7-Zip Archive ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::7-Zip Archive — combinator password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::7-Zip Archive — combinator 4 threads:::120"

    # ── RAR Archive ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::RAR Archive — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::RAR Archive — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── PDF Document ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::PDF Document — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::PDF Document — combinator 4 threads:::60"

    # ── ODT Document ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::ODT Document — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::ODT Document — combinator 4 threads:::60"

    # ── Office DOCX ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::Office DOCX — combinator password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::Office DOCX — combinator 4 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # KEEPASS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator:::KeePass Database — combinator password.txt:::600"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -t 4:::KeePass Database — combinator 4 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED COMBINATOR OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator --session my_combinator_attack:::MD5 Hash — combinator session:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -q:::MD5 Hash — combinator quiet:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator -o hashaxeed.txt:::MD5 Hash — combinator output file:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator --distributed-master:::MD5 Hash — combinator distributed master:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
