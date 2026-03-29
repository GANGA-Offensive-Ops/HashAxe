#!/bin/bash

# =============================================================================
# Hashaxe V1 - DISTRIBUTED CRACKING Test Suite
# =============================================================================
# Description: Tests all distributed cracking commands including master node
#              setup, worker node configuration, and distributed attack modes.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_9_distributed_cracking.sh
#   ./file_9_distributed_cracking.sh --resume 10
#   ./file_9_distributed_cracking.sh --dry-run
#   ./file_9_distributed_cracking.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="DISTRIBUTED CRACKING"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM) → 30s
#   Medium hashes (SSH keys, Kerberos) → 60s
#   Slow  hashes (bcrypt-10, Archives) → 180s
#
# Distributed modes:
#   --distributed-master = Run as master node
#   --distributed-worker = Run as worker node
#   --master <IP>        = Connect to master at IP
#   --work-port <port>   = Custom work port
#   --result-port <port> = Custom result port
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # MASTER NODE SETUP
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::SSH OpenSSH Key — distributed master password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::SSH PPK Key — distributed master password.txt:::180"

    # ── Master with Custom Ports ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --distributed-master --work-port 9555 --result-port 9556 -v:::SSH OpenSSH Key — distributed master custom ports:::60"

    # ── Master with Rules ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --distributed-master --rules -v:::SSH OpenSSH Key — distributed master rules:::60"

    # ── Master with Mask Attack ───────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?l?l?l?l?l?l?d?d?d' --distributed-master -v:::SSH OpenSSH Key — distributed master mask:::60"

    # ── Master with Hybrid Attack ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d?d?d' --distributed-master -v:::SSH OpenSSH Key — distributed master hybrid:::60"

    # ── Master with GPU ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --distributed-master --gpu -v:::SSH OpenSSH Key — distributed master GPU:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # MASTER BY HASH TYPE
    # ═════════════════════════════════════════════════════════════════════════

    # ── Fast Hashes ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::MD5 Hash — distributed master password.txt:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::MD5 Hash (inline) — distributed master:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::MD5 Hash (single-quoted) — distributed master:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::MD5 Hash (double-quoted) — distributed master:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::SHA-256 Hash — distributed master password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::NTLM Hash — distributed master password.txt:::30"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::NTLM Hash (inline) — distributed master:::30"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::NTLM Hash (single-quoted) — distributed master:::30"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::NTLM Hash (double-quoted) — distributed master:::30"

    # ── Slow/Very Slow Hashes ─────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::bcrypt cost-10 — distributed master password.txt:::180"

    # ── Database Hashes ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::PostgreSQL Hash hashcat — distributed master:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::PostgreSQL Hash john — distributed master:::30"

    # ── Kerberos ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::Kerberos TGS-RC4 — distributed master password.txt:::60"

    # ── Archives ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --distributed-master -v:::ZIP Archive — distributed master password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # WORKER NODE SETUP
    # ═════════════════════════════════════════════════════════════════════════

    # ── Basic Worker ───────────────────────────────────────────────────────────
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP>:::Worker node — connect to master:::60"
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP> -v:::Worker node — verbose connect to master:::60"

    # ── Worker with Custom Ports ──────────────────────────────────────────────
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP> --work-port 9555 --result-port 9556:::Worker node — custom ports:::60"

    # ── Worker with GPU ────────────────────────────────────────────────────────
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP> --gpu -v:::Worker node — GPU enabled:::60"

    # ── Multiple Workers on Same Machine ──────────────────────────────────────
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP> &:::Worker node — background worker 1:::60"
    "python3 -m hashaxe --distributed-worker --master <MASTER_IP> --gpu &:::Worker node — background GPU worker 2:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
