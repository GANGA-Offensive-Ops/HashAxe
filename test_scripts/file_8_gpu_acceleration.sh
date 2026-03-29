#!/bin/bash

# =============================================================================
# Hashaxe V1 - GPU ACCELERATION Test Suite
# =============================================================================
# Description: Tests all GPU acceleration commands including GPU detection,
#              GPU-accelerated cracking, and CPU-only fallback modes.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_8_gpu_acceleration.sh
#   ./file_8_gpu_acceleration.sh --resume 20
#   ./file_8_gpu_acceleration.sh --dry-run
#   ./file_8_gpu_acceleration.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="GPU ACCELERATION"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Info queries (--gpu-info) → 0s
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (JWT, Cisco 5, Kerberos, NetNTLM, SSH keys) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, descrypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
#
# GPU modes:
#   --gpu     = Enable GPU acceleration
#   --no-gpu  = Force CPU-only mode
#   --gpu-info = Display GPU detection info
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # GPU INFO (Info Query)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --gpu-info:::GPU detection info:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # SSH KEYS WITH GPU
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --gpu:::SSH OpenSSH Key — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --gpu -v:::SSH OpenSSH Key — GPU verbose password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --gpu:::SSH PPK Key — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASHES WITH GPU (Fast)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::MD5 Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::SHA-1 Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::SHA-256 Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::SHA-384 Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::SHA-512 Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::NTLM Hash — GPU password.txt:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --gpu:::MD5 Hash (inline) — GPU password.txt:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --gpu:::MD5 Hash (single-quoted) — GPU password.txt:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --gpu:::MD5 Hash (double-quoted) — GPU password.txt:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN HASHES WITH GPU (Slow/Very Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::bcrypt cost-4 — GPU password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::bcrypt cost-10 — GPU password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Argon2id — GPU password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::scrypt — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT WITH GPU
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::md5crypt — GPU password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::sha256crypt — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::sha512crypt — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::descrypt — GPU password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES WITH GPU (Fast)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::MySQL Hash — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::PostgreSQL Hash hashcat — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::PostgreSQL Hash john — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::MSSQL Hash — GPU password.txt:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION TOKENS WITH GPU (Medium)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::JWT HS256 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::JWT HS384 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::JWT HS512 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Ansible Vault — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO PASSWORDS WITH GPU
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Cisco Type 5 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Cisco Type 8 — GPU password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Cisco Type 9 — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS WITH GPU (Medium)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos TGS-RC4 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos AS-REP-RC4 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos TGS-AES128 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::Kerberos TGS-AES256 — GPU password.txt:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM WITH GPU (Medium)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::NetNTLMv1 — GPU password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::NetNTLMv2 — GPU password.txt:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # WINDOWS CACHED CREDENTIALS WITH GPU
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::DCC v1 — GPU password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::DCC v2 — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI WITH GPU (Very Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::DPAPI v1 — GPU password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --gpu:::DPAPI v2 — GPU password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA WITH GPU (Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --gpu:::WPA Handshake — GPU password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ARCHIVES WITH GPU (Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --gpu:::ZIP Archive — GPU password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --gpu:::7-Zip Archive — GPU password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --gpu:::RAR Archive — GPU password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # DOCUMENTS WITH GPU (Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --gpu:::PDF Document — GPU password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --gpu:::ODT Document — GPU password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGERS WITH GPU (Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --gpu:::KeePass Database — GPU password.txt:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # FORCE CPU ONLY
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --no-gpu:::SSH OpenSSH Key — CPU only password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --no-gpu:::MD5 Hash — CPU only password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --no-gpu:::bcrypt cost-10 — CPU only password.txt:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # GPU + ATTACK MODES
    # ═════════════════════════════════════════════════════════════════════════

    # ── GPU + Mask Attack ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask '?l?l?l?l?l?l?d?d?d' --gpu:::SSH OpenSSH Key — GPU mask attack:::60"

    # ── GPU + Rules Attack ────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules --gpu:::SSH OpenSSH Key — GPU rules password.txt:::60"

    # ── GPU + Hybrid Attack ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --mask '?d?d?d?d' --gpu:::SSH OpenSSH Key — GPU hybrid 4d:::60"

    # ── GPU + Session ─────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --gpu --session gpu_hashaxe:::SSH OpenSSH Key — GPU session gpu_hashaxe:::60"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
