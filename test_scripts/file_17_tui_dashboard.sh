#!/bin/bash

# =============================================================================
# Hashaxe V1 - TUI DASHBOARD Test Suite
# =============================================================================
# Description: Tests all TUI dashboard commands for real-time monitoring
#              of cracking progress across all attack modes and formats.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_17_tui_dashboard.sh
#   ./file_17_tui_dashboard.sh --resume 20
#   ./file_17_tui_dashboard.sh --dry-run
#   ./file_17_tui_dashboard.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="TUI DASHBOARD"
DEFAULT_TIMEOUT=120

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# TUI Dashboard mode:
#   --tui             = Enable Terminal User Interface dashboard
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
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --tui:::SSH OpenSSH Key — TUI wordlist:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?l?l?l?l?l?l?d?d?d' --tui:::SSH OpenSSH Key — TUI mask:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules --tui:::SSH OpenSSH Key — TUI rules:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d?d?d' --tui:::SSH OpenSSH Key — TUI hybrid:::60"

    # ── PuTTY PPK Keys ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --tui:::SSH PPK Key — TUI wordlist:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASH DIGESTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --tui:::MD5 Hash — TUI wordlist:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --mask '?l?l?l?l?l?l?l?l' --tui:::MD5 Hash — TUI mask:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --tui --gpu:::MD5 Hash — TUI GPU:::30"

    # ── SHA-256 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --tui:::SHA-256 Hash — TUI wordlist:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --mask '?l?l?l?l?l?l?l?l?d?d' --tui:::SHA-256 Hash — TUI mask:::30"

    # ── NTLM ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --tui --gpu:::NTLM Hash — TUI GPU:::30"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --tui:::PostgreSQL Hash hashcat — TUI wordlist:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --tui:::PostgreSQL Hash john — TUI wordlist:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN PASSWORD HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --tui -t 8:::bcrypt cost-10 — TUI 8 threads:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --mask '?u?l?l?l?l?l?l?d?d?d?d' --tui:::bcrypt cost-10 — TUI mask:::180"

    # ── Argon2id ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --tui -t 4:::Argon2id — TUI 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED ATTACK MODES WITH TUI
    # ═════════════════════════════════════════════════════════════════════════

    # ── PRINCE Attack ─────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack prince --prince-min 2 --prince-max 4 --tui:::MD5 Hash — TUI PRINCE:::30"

    # ── Markov Attack ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack markov --markov-order 3 --tui:::MD5 Hash — TUI Markov:::30"

    # ── PCFG Attack ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack pcfg --tui:::MD5 Hash — TUI PCFG:::30"

    # ── Combinator Attack ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --wordlist2 ${TEST_FILES_DIR}/password.txt --attack combinator --tui:::MD5 Hash — TUI combinator:::30"

    # ── AI Generation ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --ai --candidates 5000 --tui:::MD5 Hash — TUI AI generation:::30"

    # ── OSINT Profiling ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --osint-file ${TEST_FILES_DIR}/password.txt --tui:::MD5 Hash — TUI OSINT:::30"

    # ── Policy Attack ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=8,upper,digit,symbol' --tui:::MD5 Hash — TUI policy:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # TUI WITH SESSION MANAGEMENT
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --tui --session my_tui_attack:::MD5 Hash — TUI session:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --tui --restore:::MD5 Hash — TUI restore:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # TUI WITH DISTRIBUTED CRACKING
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --tui --distributed-master:::MD5 Hash — TUI distributed master:::30"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
