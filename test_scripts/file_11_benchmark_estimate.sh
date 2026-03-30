#!/bin/bash

# =============================================================================
# Hashaxe V1 - BENCHMARK & ESTIMATE Test Suite
# =============================================================================
# Description: Tests all benchmark and estimate commands for performance
#              measurement across all supported hash types and configurations.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_12_benchmark_estimate.sh
#   ./file_12_benchmark_estimate.sh --resume 20
#   ./file_12_benchmark_estimate.sh --dry-run
#   ./file_12_benchmark_estimate.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="BENCHMARK & ESTIMATE"
DEFAULT_TIMEOUT=0

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Benchmark and Estimate modes:
#   --benchmark     = Run performance benchmark
#   --estimate N    = Estimate time for N candidates
#   --gpu-info      = Display GPU detection info
#
# Note: Benchmarks and estimates are fast operations (0s timeout)
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # GPU INFO
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe --gpu-info:::GPU detection info:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --benchmark:::SSH OpenSSH Key — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --benchmark:::SSH PPK Key — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - RAW HASHES (Fast)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --benchmark:::MD5 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt --benchmark:::SHA-1 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt --benchmark:::SHA-224 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --benchmark:::SHA-256 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt --benchmark:::SHA-384 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --benchmark:::SHA-512 Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --benchmark:::NTLM Hash — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - MODERN HASHES (Slow/Very Slow)
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --benchmark:::bcrypt cost-4 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --benchmark:::bcrypt cost-10 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --benchmark:::Argon2id — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --benchmark:::scrypt — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - UNIX CRYPT
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --benchmark:::md5crypt — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt --benchmark:::sha256crypt — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --benchmark:::sha512crypt — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt --benchmark:::descrypt — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --benchmark:::MySQL Hash — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --benchmark:::PostgreSQL Hash hashcat — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --benchmark:::PostgreSQL Hash john — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --benchmark:::MSSQL Hash — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --benchmark:::JWT HS256 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt --benchmark:::JWT HS384 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt --benchmark:::JWT HS512 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --benchmark:::Ansible Vault — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - CISCO PASSWORDS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --benchmark:::Cisco Type 5 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --benchmark:::Cisco Type 8 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --benchmark:::Cisco Type 9 — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - KERBEROS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --benchmark:::Kerberos TGS-RC4 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --benchmark:::Kerberos AS-REP-RC4 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt --benchmark:::Kerberos TGS-AES128 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --benchmark:::Kerberos TGS-AES256 — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - NETNTLM
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --benchmark:::NetNTLMv1 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --benchmark:::NetNTLMv2 — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - WINDOWS CACHED CREDENTIALS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt --benchmark:::DCC v1 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt --benchmark:::DCC v2 — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - DPAPI
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --benchmark:::DPAPI v1 — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --benchmark:::DPAPI v2 — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - WIRELESS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --benchmark:::WPA Handshake — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --benchmark:::ZIP Archive — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z --benchmark:::7-Zip Archive — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar --benchmark:::RAR Archive — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --benchmark:::PDF Document — benchmark:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt --benchmark:::ODT Document — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK - PASSWORD MANAGERS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --benchmark:::KeePass Database — benchmark:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK WITH GPU
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --benchmark --gpu:::MD5 Hash — benchmark GPU:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --benchmark --gpu:::NTLM Hash — benchmark GPU:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # BENCHMARK WITH THREADS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --benchmark --threads 32:::MD5 Hash — benchmark 32 threads:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --benchmark --threads 16:::bcrypt cost-4 — benchmark 16 threads:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --estimate 1000000:::SSH OpenSSH Key — estimate 1M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --estimate 14344391:::SSH OpenSSH Key — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --estimate 1000000:::SSH PPK Key — estimate 1M:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - RAW HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --estimate 14344391:::MD5 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt --estimate 14344391:::SHA-1 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --estimate 14344391:::SHA-256 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt --estimate 14344391:::SHA-384 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --estimate 14344391:::SHA-512 Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --estimate 14344391:::NTLM Hash — estimate 14M:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - MODERN HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --estimate 1000000:::bcrypt cost-4 — estimate 1M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --estimate 100000:::bcrypt cost-10 — estimate 100K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --estimate 10000:::Argon2id — estimate 10K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --estimate 10000:::scrypt — estimate 10K:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - UNIX CRYPT
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --estimate 14344391:::md5crypt — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt --estimate 100000:::sha256crypt — estimate 100K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --estimate 100000:::sha512crypt — estimate 100K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt --estimate 14344391:::descrypt — estimate 14M:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --estimate 14344391:::MySQL Hash — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --estimate 14344391:::PostgreSQL Hash hashcat — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --estimate 14344391:::PostgreSQL Hash john — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --estimate 14344391:::MSSQL Hash — estimate 14M:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --estimate 14344391:::JWT HS256 — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --estimate 10000:::Ansible Vault — estimate 10K:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - KERBEROS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --estimate 14344391:::Kerberos TGS-RC4 — estimate 14M:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --estimate 100000:::Kerberos TGS-AES256 — estimate 100K:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --estimate 10000:::ZIP Archive — estimate 10K:::0"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --estimate 10000:::PDF Document — estimate 10K:::0"

    # ═════════════════════════════════════════════════════════════════════════
    # ESTIMATE - PASSWORD MANAGERS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --estimate 10000:::KeePass Database — estimate 10K:::0"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
