#!/bin/bash

# =============================================================================
# Hashaxe V1 - PRINCE ATTACKS Test Suite
# =============================================================================
# Description: Tests all PRINCE (PRobability INfinite Chained Elements) attack
#              commands across all 43 format handlers.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_18_prince_attacks.sh
#   ./file_18_prince_attacks.sh --resume 20
#   ./file_18_prince_attacks.sh --dry-run
#   ./file_18_prince_attacks.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="PRINCE ATTACKS"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# PRINCE attack mode:
#   --attack prince        = Enable PRINCE attack
#   --prince-min <n>       = Minimum chain length
#   --prince-max <n>       = Maximum chain length
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, JWT, Kerberos RC4, NetNTLM, Cisco 5) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SSH PRIVATE KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── OpenSSH Keys ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --attack prince:::SSH OpenSSH Key — PRINCE default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --attack prince --prince-min 2 --prince-max 6:::SSH OpenSSH Key — PRINCE 2-6 words:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::SSH OpenSSH Key — PRINCE GPU:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --attack prince --prince-min 1 --prince-max 3 --session prince_attack:::SSH OpenSSH Key — PRINCE session:::60"

    # ── PuTTY PPK Keys ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --attack prince:::SSH PPK Key — PRINCE default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --attack prince --prince-min 2 --prince-max 4:::SSH PPK Key — PRINCE 2-4 words:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASH DIGESTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --attack prince:::MD5 Hash (inline) — PRINCE default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --prince-min 1 --prince-max 3:::MD5 Hash — PRINCE 1-3 words:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::MD5 Hash — PRINCE GPU:::30"

    # ── SHA-256 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::SHA-256 Hash — PRINCE default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::SHA-256 Hash — PRINCE GPU:::30"

    # ── NTLM ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::NTLM Hash — PRINCE default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::NTLM Hash — PRINCE GPU:::30"

    # ── LM Hash ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::LM Hash — PRINCE default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::LM Hash — PRINCE GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN PASSWORD HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::bcrypt cost-10 — PRINCE default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::bcrypt cost-10 — PRINCE 8 threads:::180"

    # ── Argon2id ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::Argon2id — PRINCE default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::Argon2id — PRINCE 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── md5crypt ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::md5crypt — PRINCE default:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::md5crypt — PRINCE GPU:::120"

    # ── sha512crypt ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::sha512crypt — PRINCE default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::sha512crypt — PRINCE 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── MySQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::MySQL Hash — PRINCE default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::MySQL Hash — PRINCE GPU:::30"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::PostgreSQL Hash hashcat — PRINCE GPU:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::PostgreSQL Hash john — PRINCE GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::JWT HS256 — PRINCE default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::JWT HS256 — PRINCE GPU:::60"

    # ── Ansible Vault ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --attack prince:::Ansible Vault — PRINCE default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::Ansible Vault — PRINCE 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO PASSWORD TYPES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Cisco Type 5 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::Cisco Type 5 — PRINCE GPU:::60"

    # ── Cisco Type 8 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::Cisco Type 8 — PRINCE 8 threads:::180"

    # ── Cisco Type 9 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::Cisco Type 9 — PRINCE 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberos TGS-RC4 ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::Kerberos TGS-RC4 — PRINCE GPU:::60"

    # ── Kerberos AS-REP-RC4 ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::Kerberos AS-REP-RC4 — PRINCE GPU:::60"

    # ── Kerberos TGS-AES256 ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::Kerberos TGS-AES256 — PRINCE 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::NetNTLMv1 — PRINCE GPU:::60"

    # ── NetNTLMv2 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::NetNTLMv2 — PRINCE GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # WINDOWS CACHED CREDENTIALS (DCC)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC1 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --gpu:::DCC v1 — PRINCE GPU:::30"

    # ── DCC2 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::DCC v2 — PRINCE 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI MASTERKEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::DPAPI v1 — PRINCE 8 threads:::180"

    # ── DPAPI v2 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 8:::DPAPI v2 — PRINCE 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA/WPA2 HANDSHAKES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --attack prince:::WPA Handshake — PRINCE default:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::WPA Handshake — PRINCE 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::ZIP Archive — PRINCE 4 threads:::120"

    # ── 7-Zip ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::7-Zip Archive — PRINCE 4 threads:::120"

    # ── RAR ─────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::RAR Archive — PRINCE 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── PDF ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::PDF Document — PRINCE 4 threads:::120"

    # ── ODF (LibreOffice) ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::ODT Document — PRINCE 4 threads:::120"

    # ── Office DOCX ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::Office DOCX — PRINCE 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGER DATABASES
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --attack prince -t 4:::KeePass Database — PRINCE 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --session prince_session:::MD5 Hash — PRINCE session:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -q:::MD5 Hash — PRINCE quiet:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince -o hashaxeed.txt:::MD5 Hash — PRINCE output file:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --distributed-master:::MD5 Hash — PRINCE distributed master:::30"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
