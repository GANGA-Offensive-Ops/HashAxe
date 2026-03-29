#!/bin/bash

# =============================================================================
# Hashaxe V1 - VERBOSE OUTPUT (-v) Test Suite
# =============================================================================
# Description: Same coverage as file_2 but all commands run with -v flag
#              to validate verbose output paths. Retains same timeout tiers.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_3_verbose_output.sh
#   ./file_3_verbose_output.sh --resume 20
#   ./file_3_verbose_output.sh --dry-run
#   ./file_3_verbose_output.sh --timeout 90
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="VERBOSE OUTPUT (-v)"
DEFAULT_TIMEOUT=120

# =============================================================================
# COMMAND LIST — identical structure to file_2, all commands append -v
# Format: "command:::description:::timeout_seconds"
# =============================================================================
declare -a COMMANDS=(

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt -v:::SSH OpenSSH Key — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt -v:::SSH PPK Key — password.txt -v:::60"

    # ── MD5 — Fast ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::MD5 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt -v:::MD5 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt -v:::MD5 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt -v:::MD5 Hash (double-quoted) — password.txt -v:::30"

    # ── SHA-1 — Fast ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt -v:::SHA-1 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w ${TEST_FILES_DIR}/password.txt -v:::SHA-1 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' -w ${TEST_FILES_DIR}/password.txt -v:::SHA-1 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\" -w ${TEST_FILES_DIR}/password.txt -v:::SHA-1 Hash (double-quoted) — password.txt -v:::30"

    # ── SHA-224 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt -v:::SHA-224 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01 -w ${TEST_FILES_DIR}/password.txt -v:::SHA-224 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash 'd63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01' -w ${TEST_FILES_DIR}/password.txt -v:::SHA-224 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\" -w ${TEST_FILES_DIR}/password.txt -v:::SHA-224 Hash (double-quoted) — password.txt -v:::30"

    # ── SHA-256 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt -v:::SHA-256 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -w ${TEST_FILES_DIR}/password.txt -v:::SHA-256 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' -w ${TEST_FILES_DIR}/password.txt -v:::SHA-256 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\" -w ${TEST_FILES_DIR}/password.txt -v:::SHA-256 Hash (double-quoted) — password.txt -v:::30"

    # ── SHA-384 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt -v:::SHA-384 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7 -w ${TEST_FILES_DIR}/password.txt -v:::SHA-384 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash 'a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7' -w ${TEST_FILES_DIR}/password.txt -v:::SHA-384 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7\" -w ${TEST_FILES_DIR}/password.txt -v:::SHA-384 Hash (double-quoted) — password.txt -v:::30"

    # ── SHA-512 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt -v:::SHA-512 Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 -w ${TEST_FILES_DIR}/password.txt -v:::SHA-512 Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86' -w ${TEST_FILES_DIR}/password.txt -v:::SHA-512 Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\" -w ${TEST_FILES_DIR}/password.txt -v:::SHA-512 Hash (double-quoted) — password.txt -v:::30"

    # ── NTLM — Fast ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::NTLM Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt -v:::NTLM Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt -v:::NTLM Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt -v:::NTLM Hash (double-quoted) — password.txt -v:::30"

    # ── LM — Fast (Legacy Windows) ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::LM Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash e52cac67419a9a224a3b108f3fa6cb6d -w ${TEST_FILES_DIR}/password.txt -v:::LM Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash 'e52cac67419a9a224a3b108f3fa6cb6d' -w ${TEST_FILES_DIR}/password.txt -v:::LM Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"e52cac67419a9a224a3b108f3fa6cb6d\" -w ${TEST_FILES_DIR}/password.txt -v:::LM Hash (double-quoted) — password.txt -v:::30"

    # ── bcrypt — Slow/Very-Slow ───────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::bcrypt cost-4 — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::bcrypt cost-10 — password.txt -v:::180"

    # ── Memory-Hard KDFs — Very Slow ─────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::Argon2id — password.txt -v:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::scrypt — password.txt -v:::180"

    # ── Unix Crypt ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::md5crypt — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::sha256crypt — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::sha512crypt — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::descrypt — password.txt -v:::120"

    # ── Database Hashes ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::MySQL Hash — password.txt -v:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt -v:::MySQL Hash (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt -v:::MySQL Hash (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19\" -w ${TEST_FILES_DIR}/password.txt -v:::MySQL Hash (double-quoted) — password.txt -v:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash hashcat — password.txt -v:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash john — password.txt -v:::30"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash john format (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash john format (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash john format (double-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash hashcat format (inline) — password.txt -v:::30"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash hashcat format (single-quoted) — password.txt -v:::30"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" -w ${TEST_FILES_DIR}/password.txt -v:::PostgreSQL Hash hashcat format (double-quoted) — password.txt -v:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::MSSQL Hash — password.txt -v:::30"

    # ── JWT ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt -v:::JWT HS256 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt -v:::JWT HS384 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt -v:::JWT HS512 — password.txt -v:::60"

    # ── Network / Infra ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt -v:::Ansible Vault — password.txt -v:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::Cisco Type 5 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::Cisco Type 8 — password.txt -v:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::Cisco Type 9 — password.txt -v:::180"

    # ── Kerberos ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt -v:::Kerberos TGS-RC4 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt -v:::Kerberos AS-REP-RC4 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt -v:::Kerberos TGS-AES128 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt -v:::Kerberos TGS-AES256 — password.txt -v:::60"

    # ── NetNTLM ───────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::NetNTLMv1 — password.txt -v:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::NetNTLMv2 — password.txt -v:::60"

    # ── DCC ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::DCC v1 — password.txt -v:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::DCC v2 — password.txt -v:::180"

    # ── DPAPI — Very Slow ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::DPAPI v1 — password.txt -v:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt -v:::DPAPI v2 — password.txt -v:::180"

    # ── Wireless ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt -v:::WPA Handshake — password.txt -v:::60"

    # ── Archives ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt -v:::ZIP Archive — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt -v:::7-Zip Archive — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt -v:::RAR Archive — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt -v:::PDF Document — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt -v:::ODT Document — password.txt -v:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt -v:::Office DOCX — password.txt -v:::120"

    # ── Password Managers ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt -v:::KeePass Database — password.txt -v:::120"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
