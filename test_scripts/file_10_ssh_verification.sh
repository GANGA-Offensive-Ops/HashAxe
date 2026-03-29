#!/bin/bash

# =============================================================================
# Hashaxe V1 - SSH VERIFICATION Test Suite
# =============================================================================
# Description: Tests all SSH verification commands with live SSH host validation
#              across various attack modes and configurations.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_10_ssh_verification.sh
#   ./file_10_ssh_verification.sh --resume 5
#   ./file_10_ssh_verification.sh --dry-run
#   ./file_10_ssh_verification.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="SSH VERIFICATION"
DEFAULT_TIMEOUT=60

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# SSH Verification modes:
#   --ssh-verify    = Enable SSH verification
#   --ssh-host      = Target SSH host IP
#   --verify-port      = Custom SSH port (default 22)
#   --verify-user      = SSH username
#
# Note: These tests require a live SSH server at 127.0.0.1
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # OPENSSH KEY VERIFICATION
    # ═════════════════════════════════════════════════════════════════════════

    # ── Basic OpenSSH Verification ────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify password.txt root:::60"

    # ── Custom SSH Port ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify port 22:::60"

    # ── Verbose Output ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user root -v:::SSH OpenSSH Key — verify verbose:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # PUTTY PPK KEY VERIFICATION
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user admin:::SSH PPK Key — verify password.txt admin:::180"

    # ── PPK Custom Port ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user admin:::SSH PPK Key — verify port 22 admin:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH VERIFICATION WITH ATTACK MODES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Wordlist with Custom Wordlist ─────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify password.txt root:::60"

    # ── Mask Attack ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?l?l?l?l?l?l?d?d?d' --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify mask attack:::60"

    # ── Custom Mask Pattern ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask 'shado?l?d?d?d' --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify custom mask shado:::60"

    # ── Rules Attack ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify rules password.txt:::60"

    # ── External Rule File ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify best64 rule file:::60"

    # ── Hybrid Attack ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d?d?d' --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify hybrid 4d:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH VERIFICATION WITH ACCELERATION
    # ═════════════════════════════════════════════════════════════════════════

    # ── GPU Acceleration ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --gpu --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify GPU password.txt:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH VERIFICATION WITH SESSION MANAGEMENT
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --session ssh_hashaxe --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify session ssh_hashaxe:::60"

    # ── Session Restore ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --restore --session ssh_hashaxe --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify restore session:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH VERIFICATION WITH OUTPUT CONTROL
    # ═════════════════════════════════════════════════════════════════════════

    # ── Quiet Mode ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt -q --verify-host 127.0.0.1 --verify-port 22 --verify-user root:::SSH OpenSSH Key — verify quiet:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH VERIFICATION WITH DISTRIBUTED CRACKING
    # ═════════════════════════════════════════════════════════════════════════

    # ── Distributed Master ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --distributed-master --verify-host 127.0.0.1 --verify-port 22 --verify-user root -v:::SSH OpenSSH Key — verify distributed master:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
