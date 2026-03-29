#!/bin/bash

# =============================================================================
# Hashaxe V4 - SESSION MANAGEMENT Test Suite
# =============================================================================
# Description: Tests all session management commands including session creation,
#              listing, restoration, and deletion across various attack modes.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_7_session_management.sh
#   ./file_7_session_management.sh --resume 10
#   ./file_7_session_management.sh --dry-run
#   ./file_7_session_management.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="SESSION MANAGEMENT"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM) → 30s
#   Medium hashes (SSH keys) → 60s
#   Slow  hashes (bcrypt-10) → 180s
#   Very slow (Argon2id, Archives) → 180s
#   Info queries (--list-sessions) → 0s
#
# Session modes:
#   --session <name>  = Create named session
#   --restore         = Resume latest or named session
#   --list-sessions   = List all saved sessions
#   --delete-session  = Delete named session
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # START NAMED SESSIONS
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --session openssh_hashaxe:::SSH OpenSSH Key — session openssh_hashaxe:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --session ppk_hashaxe:::SSH PPK Key — session ppk_hashaxe:::180"

    # ── Fast Hashes ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --session md5_hashaxe:::MD5 Hash — session md5_hashaxe:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --session md5_inline:::MD5 Hash (inline) — session md5_inline:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --session md5_single:::MD5 Hash (single-quoted) — session md5_single:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --session md5_double:::MD5 Hash (double-quoted) — session md5_double:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --session sha256_hashaxe:::SHA-256 Hash — session sha256_hashaxe:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --session ntlm_hashaxe:::NTLM Hash — session ntlm_hashaxe:::30"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt --session ntlm_inline:::NTLM Hash (inline) — session ntlm_inline:::30"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt --session ntlm_single:::NTLM Hash (single-quoted) — session ntlm_single:::30"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt --session ntlm_double:::NTLM Hash (double-quoted) — session ntlm_double:::30"

    # ── Slow/Very Slow Hashes ─────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --session bcrypt_hashaxe:::bcrypt cost-10 — session bcrypt_hashaxe:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --session argon2_hashaxe:::Argon2id — session argon2_hashaxe:::180"

    # ── Database Hashes ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --session pg_hashcat:::PostgreSQL Hash hashcat — session pg_hashcat:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --session pg_john:::PostgreSQL Hash john — session pg_john:::30"

    # ── Archives/Documents ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --session zip_hashaxe:::ZIP Archive — session zip_hashaxe:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --session pdf_hashaxe:::PDF Document — session pdf_hashaxe:::120"

    # ── Password Managers ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --session keepass_hashaxe:::KeePass Database — session keepass_hashaxe:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # SESSION WITH ATTACK MODES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Session with Mask Attack ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?l?l?l?l?l?l?d?d?d' --session mask_attack:::SSH OpenSSH Key — session mask_attack:::60"

    # ── Session with Rules Attack ─────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules --session rules_attack:::SSH OpenSSH Key — session rules_attack:::60"

    # ── Session with Hybrid Attack ────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d?d?d' --session hybrid_attack:::SSH OpenSSH Key — session hybrid_attack:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # LIST SESSIONS (Info Query)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --list-sessions:::List all saved sessions:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # RESTORE SESSIONS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Restore Latest Session ────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --restore:::SSH OpenSSH Key — restore latest session:::60"

    # ── Restore Named Sessions ────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --restore --session openssh_hashaxe:::SSH OpenSSH Key — restore openssh_hashaxe:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --restore --session ppk_hashaxe:::SSH PPK Key — restore ppk_hashaxe:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --restore --session md5_hashaxe:::MD5 Hash — restore md5_hashaxe:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --restore --session bcrypt_hashaxe:::bcrypt cost-10 — restore bcrypt_hashaxe:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --restore --session zip_hashaxe:::ZIP Archive — restore zip_hashaxe:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # DELETE SESSIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --delete-session openssh_hashaxe:::Delete session openssh_hashaxe:::0"
    "python3 -m hashaxe --delete-session ppk_hashaxe:::Delete session ppk_hashaxe:::0"
    "python3 -m hashaxe --delete-session md5_hashaxe:::Delete session md5_hashaxe:::0"
    "python3 -m hashaxe --delete-session bcrypt_hashaxe:::Delete session bcrypt_hashaxe:::0"
    "python3 -m hashaxe --delete-session zip_hashaxe:::Delete session zip_hashaxe:::0"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
