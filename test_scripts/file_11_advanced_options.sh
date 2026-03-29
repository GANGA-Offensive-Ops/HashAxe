#!/bin/bash

# =============================================================================
# Hashaxe V1 - ADVANCED OPTIONS Test Suite
# =============================================================================
# Description: Tests all advanced options including quiet mode, thread control,
#              custom charset definitions, and estimate-only calculations.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_11_advanced_options.sh
#   ./file_11_advanced_options.sh --resume 20
#   ./file_11_advanced_options.sh --dry-run
#   ./file_11_advanced_options.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="ADVANCED OPTIONS"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Advanced options:
#   -q / --quiet        = Suppress non-essential output
#   --threads N         = Set thread count
#   -1, -2, -3, -4      = Custom charset definitions for masks
#   --estimate N        = Estimate time for N candidates (no cracking)
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, Kerberos) → 60s
#   Slow  hashes (bcrypt-4, Archives) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt) → 180s
#   Estimate-only → 0s (instant)
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # QUIET MODE (-q)
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt -q:::SSH OpenSSH Key — quiet password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt -q:::SSH PPK Key — quiet password.txt:::180"

    # ── Fast Hashes ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt -q:::MD5 Hash — quiet password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt -q:::SHA-256 Hash — quiet password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt -q:::NTLM Hash — quiet password.txt:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt -q:::MD5 Hash (inline) — quiet password.txt:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt -q:::MD5 Hash (single-quoted) — quiet password.txt:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt -q:::MD5 Hash (double-quoted) — quiet password.txt:::30"

    # ── Slow/Very Slow Hashes ─────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt -q:::bcrypt cost-10 — quiet password.txt:::180"

    # ── Network/Kerberos ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt -q:::Kerberos TGS-RC4 — quiet password.txt:::60"

    # ── Archives ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt -q:::ZIP Archive — quiet password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # THREAD CONTROL (--threads)
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --threads 16:::SSH OpenSSH Key — 16 threads:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --threads 32:::SSH OpenSSH Key — 32 threads:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --threads 8:::SSH PPK Key — 8 threads:::180"

    # ── Fast Hashes ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --threads 32:::MD5 Hash — 32 threads:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --threads 32:::SHA-256 Hash — 32 threads:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --threads 32:::NTLM Hash — 32 threads:::30"

    # ── Slow Hashes ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --threads 16:::bcrypt cost-4 — 16 threads:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --threads 8:::bcrypt cost-10 — 8 threads:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --threads 4:::Argon2id — 4 threads:::180"

    # ── Archives/Documents ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --threads 8:::ZIP Archive — 8 threads:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --threads 8:::PDF Document — 8 threads:::120"

    # ── Password Managers ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --threads 4:::KeePass Database — 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # CUSTOM CHARSET DEFINITIONS (-1, -2, -3, -4)
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys with Custom Charsets ─────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?1?1?1?1?1?1?1?1?1' -1 '?l?d':::SSH OpenSSH Key — charset ?l?d 9-char:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?1?1?1?1?1?1' -1 'abc123':::SSH OpenSSH Key — charset abc123 6-char:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask 'pass?1?2r?1' -1 'pwd' -2 'aou':::SSH OpenSSH Key — dual charset:::60"

    # ── Fast Hashes with Custom Charsets ──────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::MD5 Hash — charset ?l?d 8-char:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::SHA-256 Hash — charset ?l?d 8-char:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?u?d':::NTLM Hash — charset ?l?u?d 8-char:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::MD5 Hash (inline) — charset ?l?d 8-char:::30"

    # ── Slow Hashes with Custom Charsets ──────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --mask '?1?1?1?1?1?1?1?1?1' -1 '?l?d':::bcrypt cost-4 — charset ?l?d 9-char:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --mask 'Shadow?1?1?1?1' -1 '0123456789':::Argon2id — charset Shadow+4d:::180"

    # ── Database Hashes with Custom Charsets ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::MySQL Hash — charset ?l?d 8-char:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::PostgreSQL Hash hashcat — charset ?l?d 8-char:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?d':::PostgreSQL Hash john — charset ?l?d 8-char:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --mask '?1?1?1?1?1?1?1?1' -1 '?l?u?d':::MSSQL Hash — charset ?l?u?d 8-char:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE ONLY (--estimate)
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --estimate 1000000:::SSH OpenSSH Key — estimate 1M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --estimate 14344391:::SSH OpenSSH Key — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --estimate 1000000:::SSH PPK Key — estimate 1M:::0"

    # ── Fast Hashes ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --estimate 14344391:::MD5 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --estimate 14344391:::SHA-256 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --estimate 14344391:::NTLM Hash — estimate 14M:::0"

    # ── Slow/Very Slow Hashes ─────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --estimate 1000000:::bcrypt cost-4 — estimate 1M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --estimate 100000:::bcrypt cost-10 — estimate 100K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --estimate 10000:::Argon2id — estimate 10K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --estimate 10000:::scrypt — estimate 10K:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # COMBINED OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Quiet + Threads ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt -q --threads 32:::MD5 Hash — quiet 32 threads:::30"

    # ── Custom Charset + Threads ────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?1?1?1?1?1?1?1?1?1' -1 '?l?d' --threads 16:::SSH OpenSSH Key — charset + 16 threads:::60"

    # ── GPU + Quiet ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu -q:::MD5 Hash — GPU quiet:::30"

    # ── All Options Combined ──────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --threads 32 --gpu -q --session optimized_attack:::SSH OpenSSH Key — all options combined:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
