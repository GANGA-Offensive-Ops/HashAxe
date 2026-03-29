#!/bin/bash

# =============================================================================
# Hashaxe V1 - BASIC OPERATIONS / --info Test Suite
# =============================================================================
# Description: Runs all --info commands sequentially. No timeout (these are
#              fast metadata queries). Press Ctrl+C to skip current command.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_1_basic_operation_info_commands.sh
#   ./file_1_basic_operation_info_commands.sh --resume 15
#   ./file_1_basic_operation_info_commands.sh --dry-run
# =============================================================================

# Source shared library (must be in same directory as this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

# Suite identity
SUITE_NAME="BASIC OPERATIONS — INFO"
DEFAULT_TIMEOUT=0    # No timeout for --info commands (all return quickly)

# =============================================================================
# COMMAND LIST
# Format: "command:::description"
#
# FIXES vs v1.0:
#   - All `python` normalized to `python3`
#   - TOTAL_COMMANDS no longer hardcoded here — computed from array length
# =============================================================================
declare -a COMMANDS=(

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --info:::SSH OpenSSH Key Info"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --info:::SSH PPK Key Info"

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --info:::MD5 Hash (file)"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --info:::MD5 Hash (inline)"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' --info:::MD5 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" --info:::MD5 Hash (double-quoted)"

    # ── SHA-1 ─────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt --info:::SHA-1 Hash (file)"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --info:::SHA-1 Hash (inline)"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' --info:::SHA-1 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\" --info:::SHA-1 Hash (double-quoted)"

    # ── SHA-224 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt --info:::SHA-224 Hash (file)"
    "python3 -m hashaxe --hash d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01 --info:::SHA-224 Hash (inline)"
    "python3 -m hashaxe --hash 'd63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01' --info:::SHA-224 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\" --info:::SHA-224 Hash (double-quoted)"

    # ── SHA-256 ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --info:::SHA-256 Hash (file)"
    "python3 -m hashaxe --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --info:::SHA-256 Hash (inline)"
    "python3 -m hashaxe --hash '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' --info:::SHA-256 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\" --info:::SHA-256 Hash (double-quoted)"

    # ── SHA-384 ───────────────────────────────────────────────────────────────
    # NOTE: SHA-384 digest is 96 hex chars. Verify your test hash is the correct
    # digest for your test input — truncated hashes will fail to match.
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt --info:::SHA-384 Hash (file)"
    "python3 -m hashaxe --hash a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7 --info:::SHA-384 Hash (inline)"
    "python3 -m hashaxe --hash 'a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7' --info:::SHA-384 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7\" --info:::SHA-384 Hash (double-quoted)"

    # ── SHA-512 ───────────────────────────────────────────────────────────────
    # NOTE: SHA-512 digest is 128 hex chars. Verify your test hash length.
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --info:::SHA-512 Hash (file)"
    "python3 -m hashaxe --hash b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 --info:::SHA-512 Hash (inline)"
    "python3 -m hashaxe --hash 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86' --info:::SHA-512 Hash (single-quoted)"
    "python3 -m hashaxe --hash \"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\" --info:::SHA-512 Hash (double-quoted)"

    # ── NTLM / LM ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --info:::NTLM Hash (file)"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c --info:::NTLM Hash (inline)"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' --info:::NTLM Hash (single-quoted)"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" --info:::NTLM Hash (double-quoted)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt --info:::LM Hash (file)"
    "python3 -m hashaxe --hash e52cac67419a9a224a3b108f3fa6cb6d --info:::LM Hash (inline)"
    "python3 -m hashaxe --hash 'e52cac67419a9a224a3b108f3fa6cb6d' --info:::LM Hash (single-quoted)"
    "python3 -m hashaxe --hash \"e52cac67419a9a224a3b108f3fa6cb6d\" --info:::LM Hash (double-quoted)"

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --info:::bcrypt cost-4 Hash (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --info:::bcrypt cost-10 Hash (file)"

    # ── Memory-Hard KDFs ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --info:::Argon2id Hash (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --info:::scrypt Hash (file)"

    # ── Unix Crypt variants ───────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --info:::md5crypt Hash (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt --info:::sha256crypt Hash (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --info:::sha512crypt Hash (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt --info:::descrypt Hash (file)"

    # ── Database Hashes ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --info:::MySQL Hash (file)"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' --info:::MySQL Hash (inline)"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' --info:::MySQL Hash (single-quoted)"
    "python3 -m hashaxe --hash \"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19\" --info:::MySQL Hash (double-quoted)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --info:::PostgreSQL Hash hashcat (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --info:::PostgreSQL Hash john (file)"
    "python3 -m hashaxe --hash md50a245ea64f49f9aa79fa9c79bbd95c8d --info:::PostgreSQL Hash (inline)"
    "python3 -m hashaxe --hash 'md50a245ea64f49f9aa79fa9c79bbd95c8d' --info:::PostgreSQL Hash (single-quoted)"
    "python3 -m hashaxe --hash \"md50a245ea64f49f9aa79fa9c79bbd95c8d\" --info:::PostgreSQL Hash (double-quoted)"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d --info:::PostgreSQL Hash john format (inline)"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' --info:::PostgreSQL Hash john format (single-quoted)"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" --info:::PostgreSQL Hash john format (double-quoted)"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin --info:::PostgreSQL Hash hashcat format (inline)"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' --info:::PostgreSQL Hash hashcat format (single-quoted)"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" --info:::PostgreSQL Hash hashcat format (double-quoted)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --info:::MSSQL Hash (file)"

    # ── JWT ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --info:::JWT HS256 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt --info:::JWT HS384 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt --info:::JWT HS512 (file)"

    # ── Network / Infra ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --info:::Ansible Vault (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --info:::Cisco Type 5 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --info:::Cisco Type 8 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --info:::Cisco Type 9 (file)"

    # ── Kerberos ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --info:::Kerberos TGS RC4 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --info:::Kerberos AS-REP RC4 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt --info:::Kerberos TGS AES128 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --info:::Kerberos TGS AES256 (file)"

    # ── NetNTLM / DCC ─────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --info:::NetNTLMv1 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --info:::NetNTLMv2 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt --info:::DCC v1 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt --info:::DCC v2 (file)"

    # ── DPAPI ─────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --info:::DPAPI v1 (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --info:::DPAPI v2 (file)"

    # ── Wireless ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --info:::WPA Handshake (file)"

    # ── Archives ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --info:::ZIP Archive (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z --info:::7-Zip Archive (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar --info:::RAR Archive (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --info:::PDF Document (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt --info:::ODT Document (file)"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx --info:::Office DOCX (file)"

    # ── Password Managers ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --info:::KeePass Database (file)"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
