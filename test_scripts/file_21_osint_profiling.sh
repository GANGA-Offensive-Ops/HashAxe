#!/bin/bash

# =============================================================================
# Hashaxe V1 - OSINT PROFILING Test Suite
# =============================================================================
# Description: Tests all OSINT-powered password candidate generation commands
#              across all 43 format handlers.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_21_osint_profiling.sh
#   ./file_21_osint_profiling.sh --resume 20
#   ./file_21_osint_profiling.sh --dry-run
#   ./file_21_osint_profiling.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="OSINT PROFILING"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# OSINT profiling mode:
#   --osint-file <file>    = OSINT intelligence source file
#   --osint-export <file>  = Export OSINT wordlist without cracking
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, JWT, Kerberos RC4, NetNTLM, Cisco 5) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # BASIC USAGE - OSINT EXPORT
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --osint-file ${TEST_FILES_DIR}/password.txt --osint-export /tmp/osint_wordlist.txt:::OSINT — export wordlist only:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH PRIVATE KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── OpenSSH Keys ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --osint-file ${TEST_FILES_DIR}/password.txt:::SSH OpenSSH Key — OSINT default:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --osint-file ${TEST_FILES_DIR}/password.txt --session osint_attack:::SSH OpenSSH Key — OSINT session:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --osint-file ${TEST_FILES_DIR}/password.txt -v:::SSH OpenSSH Key — OSINT verbose:::60"

    # ── PuTTY PPK Keys ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --osint-file ${TEST_FILES_DIR}/password.txt:::SSH PPK Key — OSINT default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::SSH PPK Key — OSINT 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASH DIGESTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --osint-file ${TEST_FILES_DIR}/password.txt:::MD5 Hash (inline) — OSINT default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt:::MD5 Hash — OSINT default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::MD5 Hash — OSINT GPU:::30"

    # ── SHA-256 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --osint-file ${TEST_FILES_DIR}/password.txt:::SHA-256 Hash — OSINT default:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::SHA-256 Hash — OSINT GPU:::30"

    # ── NTLM ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::NTLM Hash — OSINT GPU:::30"

    # ── LM Hash ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::LM Hash — OSINT GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN PASSWORD HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt:::bcrypt cost-10 — OSINT default:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::bcrypt cost-10 — OSINT 8 threads:::180"

    # ── Argon2id ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::Argon2id — OSINT 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── md5crypt ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::md5crypt — OSINT GPU:::120"

    # ── sha512crypt ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::sha512crypt — OSINT 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── MySQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::MySQL Hash — OSINT GPU:::30"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::PostgreSQL Hash hashcat — OSINT GPU:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::PostgreSQL Hash john — OSINT GPU:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::JWT HS256 — OSINT GPU:::60"

    # ── Ansible Vault ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::Ansible Vault — OSINT 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO PASSWORD TYPES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Cisco Type 5 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::Cisco Type 5 — OSINT GPU:::60"

    # ── Cisco Type 8 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::Cisco Type 8 — OSINT 8 threads:::180"

    # ── Cisco Type 9 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::Cisco Type 9 — OSINT 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberos TGS-RC4 ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos TGS-RC4 — OSINT GPU:::60"

    # ── Kerberos AS-REP-RC4 ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos AS-REP-RC4 — OSINT GPU:::60"

    # ── Kerberos TGS-AES256 ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::Kerberos TGS-AES256 — OSINT 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::NetNTLMv1 — OSINT GPU:::60"

    # ── NetNTLMv2 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::NetNTLMv2 — OSINT GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # WINDOWS CACHED CREDENTIALS (DCC)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC1 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --gpu:::DCC v1 — OSINT GPU:::30"

    # ── DCC2 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::DCC v2 — OSINT 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI MASTERKEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::DPAPI v1 — OSINT 8 threads:::180"

    # ── DPAPI v2 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -t 8:::DPAPI v2 — OSINT 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA/WPA2 HANDSHAKES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::WPA Handshake — OSINT 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::ZIP Archive — OSINT 4 threads:::120"

    # ── 7-Zip ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::7-Zip Archive — OSINT 4 threads:::120"

    # ── RAR ─────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::RAR Archive — OSINT 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── PDF ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::PDF Document — OSINT 4 threads:::120"

    # ── ODF (LibreOffice) ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::ODT Document — OSINT 4 threads:::120"

    # ── Office DOCX ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::Office DOCX — OSINT 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGER DATABASES
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --osint-file ${TEST_FILES_DIR}/password.txt -t 4:::KeePass Database — OSINT 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --session osint_session:::MD5 Hash — OSINT session:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -q:::MD5 Hash — OSINT quiet:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt -o hashaxeed.txt:::MD5 Hash — OSINT output file:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --distributed-master:::MD5 Hash — OSINT distributed master:::30"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
