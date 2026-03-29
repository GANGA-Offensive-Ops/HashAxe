#!/bin/bash

# =============================================================================
# Hashaxe V4 - AI GENERATION Test Suite
# =============================================================================
# Description: Tests all AI-powered candidate generation commands using GPT-2
#              and Markov fallback across all 43 format handlers.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_14_ai_generation.sh
#   ./file_14_ai_generation.sh --resume 20
#   ./file_14_ai_generation.sh --dry-run
#   ./file_14_ai_generation.sh --timeout 120
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="AI GENERATION"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# AI Generation mode:
#   --ai              = Enable AI-powered candidate generation
#   --candidates N    = Number of candidates to generate (default: 1000)
#   --download-models = Download GPT-2 models for offline use
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, JWT, Kerberos RC4, NetNTLM, Cisco 5) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SETUP
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --download-models:::Download AI models:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASH DIGESTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --ai:::MD5 Hash (inline) — AI default:::60"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' --ai:::MD5 Hash (single-quoted) — AI default:::60"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" --ai:::MD5 Hash (double-quoted) — AI default:::60"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --ai --candidates 5000:::MD5 Hash (inline) — AI 5000 candidates:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai:::MD5 Hash — AI default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 2000 --gpu:::MD5 Hash — AI GPU:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --ai:::MD5 Hash — AI wordlist fallback:::60"

    # ── SHA-256 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --ai:::SHA-256 Hash — AI default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --ai --candidates 3000:::SHA-256 Hash — AI 3000 candidates:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --ai --candidates 2000 --gpu:::SHA-256 Hash — AI GPU:::60"

    # ── SHA-512 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --ai:::SHA-512 Hash — AI default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --ai --candidates 5000 --gpu:::SHA-512 Hash — AI GPU 5000:::60"

    # ── NTLM ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --ai:::NTLM Hash — AI default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --ai --candidates 2000 --gpu:::NTLM Hash — AI GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN PASSWORD HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --ai --candidates 500:::bcrypt cost-10 — AI 500:::600"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --ai --candidates 1000 -t 8:::bcrypt cost-10 — AI 8 threads:::600"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --ai:::bcrypt cost-10 — AI wordlist fallback:::600"

    # ── Argon2id ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --ai --candidates 500:::Argon2id — AI 500:::600"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --ai --candidates 500 -t 4:::Argon2id — AI 4 threads:::600"

    # ── scrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --ai --candidates 500 -t 4:::scrypt — AI 4 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH PRIVATE KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── OpenSSH Keys ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --ai --candidates 1000:::SSH OpenSSH Key — AI 1000:::300"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --ai:::SSH OpenSSH Key — AI wordlist fallback:::300"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --ai --candidates 2000 --session ai_attack:::SSH OpenSSH Key — AI session:::300"

    # ── PuTTY PPK Keys ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --ai --candidates 500:::SSH PPK Key — AI 500:::600"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --ai --candidates 1000 -t 4:::SSH PPK Key — AI 4 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── md5crypt ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --ai --candidates 2000 --gpu:::md5crypt — AI GPU:::300"

    # ── sha512crypt ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --ai --candidates 500 -t 8:::sha512crypt — AI 8 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── MySQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --ai --candidates 2000 --gpu:::MySQL Hash — AI GPU:::60"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --ai --candidates 2000 --gpu:::PostgreSQL Hash hashcat — AI GPU:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --ai --candidates 2000 --gpu:::PostgreSQL Hash john — AI GPU:::60"

    # ── MSSQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --ai --candidates 2000 --gpu:::MSSQL Hash — AI GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --ai --candidates 2000 --gpu:::JWT HS256 — AI GPU:::300"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt --ai --candidates 2000 --gpu:::JWT HS384 — AI GPU:::300"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt --ai --candidates 2000 --gpu:::JWT HS512 — AI GPU:::300"

    # ── Ansible Vault ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --ai --candidates 500 -t 4:::Ansible Vault — AI 4 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO PASSWORD TYPES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Cisco Type 5 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --ai --candidates 2000 --gpu:::Cisco Type 5 — AI GPU:::300"

    # ── Cisco Type 8 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --ai --candidates 500 -t 8:::Cisco Type 8 — AI 8 threads:::600"

    # ── Cisco Type 9 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --ai --candidates 500 -t 4:::Cisco Type 9 — AI 4 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberos TGS-RC4 ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --ai --candidates 2000 --gpu:::Kerberos TGS-RC4 — AI GPU:::300"

    # ── Kerberos AS-REP-RC4 ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --ai --candidates 2000 --gpu:::Kerberos AS-REP-RC4 — AI GPU:::300"

    # ── Kerberos TGS-AES128 ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt --ai --candidates 500 -t 8:::Kerberos TGS-AES128 — AI 8 threads:::300"

    # ── Kerberos TGS-AES256 ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --ai --candidates 500 -t 8:::Kerberos TGS-AES256 — AI 8 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --ai --candidates 2000 --gpu:::NetNTLMv1 — AI GPU:::300"

    # ── NetNTLMv2 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --ai --candidates 2000 --gpu:::NetNTLMv2 — AI GPU:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # WINDOWS CACHED CREDENTIALS (DCC)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC1 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt --ai --candidates 2000 --gpu:::DCC v1 — AI GPU:::60"

    # ── DCC2 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt --ai --candidates 500 -t 8:::DCC v2 — AI 8 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI MASTERKEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --ai --candidates 500 -t 8:::DPAPI v1 — AI 8 threads:::600"

    # ── DPAPI v2 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --ai --candidates 500 -t 8:::DPAPI v2 — AI 8 threads:::600"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA/WPA2 HANDSHAKES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --ai --candidates 500 -t 4:::WPA Handshake — AI 4 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --ai --candidates 500 -t 4:::ZIP Archive — AI 4 threads:::300"

    # ── 7-Zip ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z --ai --candidates 500 -t 4:::7-Zip Archive — AI 4 threads:::300"

    # ── RAR ─────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar --ai --candidates 500 -t 4:::RAR Archive — AI 4 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── PDF ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --ai --candidates 500 -t 4:::PDF Document — AI 4 threads:::300"

    # ── ODF (LibreOffice) ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt --ai --candidates 500 -t 4:::ODT Document — AI 4 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGER DATABASES
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --ai --candidates 500 -t 4:::KeePass Database — AI 4 threads:::300"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 --session ai_session:::MD5 Hash — AI session:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 -q:::MD5 Hash — AI quiet:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 -o hashaxeed.txt:::MD5 Hash — AI output file:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 -v:::MD5 Hash — AI verbose:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 --distributed-master:::MD5 Hash — AI distributed master:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
