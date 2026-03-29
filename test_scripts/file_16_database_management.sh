#!/bin/bash

# =============================================================================
# Hashaxe V1 - DATABASE MANAGEMENT Test Suite
# =============================================================================
# Description: Tests all database management commands for results storage,
#              querying, filtering, exporting, and statistics.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_16_database_management.sh
#   ./file_16_database_management.sh --resume 20
#   ./file_16_database_management.sh --dry-run
#   ./file_16_database_management.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="DATABASE MANAGEMENT"
DEFAULT_TIMEOUT=30

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Database management options:
#   --show-results     = Display all hashaxeed passwords
#   --stats            = Display aggregate statistics
#   --export-results   = Export results to JSON/CSV
#   --clear-results    = Delete all results (DESTRUCTIVE)
#   --filter-format    = Filter by format ID
#
# Note: Database commands are fast operations (30s timeout)
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # BASIC COMMANDS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Show All Results ─────────────────────────────────────────────────────
    "python3 -m hashaxe --show-results:::Show all hashaxeed passwords:::30"

    # ── Statistics ───────────────────────────────────────────────────────────
    "python3 -m hashaxe --stats:::Show aggregate statistics:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - RAW HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format hash.md5:::Filter results by MD5:::30"
    "python3 -m hashaxe --show-results --filter-format hash.sha1:::Filter results by SHA-1:::30"
    "python3 -m hashaxe --show-results --filter-format hash.sha256:::Filter results by SHA-256:::30"
    "python3 -m hashaxe --show-results --filter-format hash.sha512:::Filter results by SHA-512:::30"
    "python3 -m hashaxe --show-results --filter-format hash.ntlm:::Filter results by NTLM:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - MODERN HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format hash.bcrypt:::Filter results by bcrypt:::30"
    "python3 -m hashaxe --show-results --filter-format hash.argon2:::Filter results by Argon2:::30"
    "python3 -m hashaxe --show-results --filter-format hash.scrypt:::Filter results by scrypt:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format ssh.openssh:::Filter results by SSH OpenSSH:::30"
    "python3 -m hashaxe --show-results --filter-format ssh.ppk:::Filter results by SSH PPK:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format archive.zip:::Filter results by ZIP:::30"
    "python3 -m hashaxe --show-results --filter-format archive.7z:::Filter results by 7-Zip:::30"
    "python3 -m hashaxe --show-results --filter-format archive.rar:::Filter results by RAR:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format document.pdf:::Filter results by PDF:::30"
    "python3 -m hashaxe --show-results --filter-format document.odf:::Filter results by ODF:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format token.jwt:::Filter results by JWT:::30"
    "python3 -m hashaxe --show-results --filter-format token.ansible_vault:::Filter results by Ansible Vault:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # FILTER BY FORMAT - NETWORK
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --show-results --filter-format network.cisco_type5:::Filter results by Cisco Type 5:::30"
    "python3 -m hashaxe --show-results --filter-format network.krb5tgs_rc4:::Filter results by Kerberos TGS-RC4:::30"
    "python3 -m hashaxe --show-results --filter-format network.netntlmv2:::Filter results by NetNTLMv2:::30"
    "python3 -m hashaxe --show-results --filter-format network.dcc1:::Filter results by DCC v1:::30"
    "python3 -m hashaxe --show-results --filter-format network.wpa:::Filter results by WPA:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # EXPORT TO JSON
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --export-results /tmp/results.json:::Export all results to JSON:::30"
    "python3 -m hashaxe --export-results /tmp/md5_results.json --filter-format hash.md5:::Export MD5 results to JSON:::30"
    "python3 -m hashaxe --export-results /tmp/ssh_results.json --filter-format ssh.openssh:::Export SSH results to JSON:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # EXPORT TO CSV
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --export-results /tmp/results.csv:::Export all results to CSV:::30"
    "python3 -m hashaxe --export-results /tmp/bcrypt_results.csv --filter-format hash.bcrypt:::Export bcrypt results to CSV:::30"
    "python3 -m hashaxe --export-results /tmp/jwt_results.csv --filter-format token.jwt:::Export JWT results to CSV:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # CLEAR RESULTS (DESTRUCTIVE - commented out for safety)
    # ═════════════════════════════════════════════════════════════════════════

    # WARNING: Uncomment only if you want to test destructive operation
    # "python3 -m hashaxe --clear-results:::Clear all results (DESTRUCTIVE):::30"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
