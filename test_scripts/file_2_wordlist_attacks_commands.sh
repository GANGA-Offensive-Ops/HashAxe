#!/bin/bash

# =============================================================================
# Hashaxe V1 - WORDLIST ATTACKS Test Suite
# =============================================================================
# Description: Runs all wordlist attack (-w) commands sequentially.
#              Per-command timeouts prevent slow hashes (bcrypt/Argon2id)
#              from blocking the full suite.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_2_wordlist_attacks_commands.sh
#   ./file_2_wordlist_attacks_commands.sh --resume 30
#   ./file_2_wordlist_attacks_commands.sh --dry-run
#   ./file_2_wordlist_attacks_commands.sh --timeout 60    # override all timeouts
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="WORDLIST ATTACKS"
DEFAULT_TIMEOUT=120    # Fallback timeout if not specified per-command

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL) → 30s
#   Medium hashes (SHA-crypt, JWT, Cisco 5, Kerberos, NetNTLM) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, descrypt, WPA, Archives) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
#
# FIXES vs v1.0:
#   - All `python` normalized to `python3`
#   - TOTAL_COMMANDS no longer hardcoded — computed from array length
#   - TIMEOUT tracking fixed: exit 124 from coreutils `timeout`, not wall-clock hack
#   - TIMEOUT message now shows actual per-command timeout, not DEFAULT_TIMEOUT
# =============================================================================
declare -a COMMANDS=(

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt:::SSH OpenSSH Key — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt:::SSH PPK Key — password.txt:::60"

    # ── MD5 — Fast ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt:::MD5 Hash — password.txt:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt:::MD5 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt:::MD5 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt:::MD5 Hash (double-quoted) — password.txt:::30"

    # ── SHA-1 — Fast ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt:::SHA-1 Hash — password.txt:::30"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w ${TEST_FILES_DIR}/password.txt:::SHA-1 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' -w ${TEST_FILES_DIR}/password.txt:::SHA-1 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\" -w ${TEST_FILES_DIR}/password.txt:::SHA-1 Hash (double-quoted) — password.txt:::30"

    # ── SHA-224 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt:::SHA-224 Hash — password.txt:::30"
    "python3 -m hashaxe --hash d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01 -w ${TEST_FILES_DIR}/password.txt:::SHA-224 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash 'd63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01' -w ${TEST_FILES_DIR}/password.txt:::SHA-224 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\" -w ${TEST_FILES_DIR}/password.txt:::SHA-224 Hash (double-quoted) — password.txt:::30"

    # ── SHA-256 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt:::SHA-256 Hash — password.txt:::30"
    "python3 -m hashaxe --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -w ${TEST_FILES_DIR}/password.txt:::SHA-256 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' -w ${TEST_FILES_DIR}/password.txt:::SHA-256 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\" -w ${TEST_FILES_DIR}/password.txt:::SHA-256 Hash (double-quoted) — password.txt:::30"

    # ── SHA-384 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt:::SHA-384 Hash — password.txt:::30"
    "python3 -m hashaxe --hash a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7 -w ${TEST_FILES_DIR}/password.txt:::SHA-384 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash 'a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7' -w ${TEST_FILES_DIR}/password.txt:::SHA-384 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7\" -w ${TEST_FILES_DIR}/password.txt:::SHA-384 Hash (double-quoted) — password.txt:::30"

    # ── SHA-512 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt:::SHA-512 Hash — password.txt:::30"
    "python3 -m hashaxe --hash b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 -w ${TEST_FILES_DIR}/password.txt:::SHA-512 Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86' -w ${TEST_FILES_DIR}/password.txt:::SHA-512 Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\" -w ${TEST_FILES_DIR}/password.txt:::SHA-512 Hash (double-quoted) — password.txt:::30"

    # ── NTLM — Fast ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt:::NTLM Hash — password.txt:::30"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt:::NTLM Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt:::NTLM Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt:::NTLM Hash (double-quoted) — password.txt:::30"

    # ── LM — Fast (Legacy Windows) ────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt:::LM Hash — password.txt:::30"
    "python3 -m hashaxe --hash e52cac67419a9a224a3b108f3fa6cb6d -w ${TEST_FILES_DIR}/password.txt:::LM Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash 'e52cac67419a9a224a3b108f3fa6cb6d' -w ${TEST_FILES_DIR}/password.txt:::LM Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"e52cac67419a9a224a3b108f3fa6cb6d\" -w ${TEST_FILES_DIR}/password.txt:::LM Hash (double-quoted) — password.txt:::30"

    # ── bcrypt — Slow/Very-Slow ───────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt:::bcrypt cost-4 — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt:::bcrypt cost-10 — password.txt:::180"

    # ── Memory-Hard KDFs — Very Slow ─────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt:::Argon2id — password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt:::scrypt — password.txt:::180"

    # ── Unix Crypt — Medium/Slow ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt:::md5crypt — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt:::sha256crypt — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt:::sha512crypt — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt:::descrypt — password.txt:::120"

    # ── Database Hashes ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt:::MySQL Hash — password.txt:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt:::MySQL Hash (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt:::MySQL Hash (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19\" -w ${TEST_FILES_DIR}/password.txt:::MySQL Hash (double-quoted) — password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash hashcat — password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash john — password.txt:::30"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash john format (inline) — password.txt:::30"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash john format (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash john format (double-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash hashcat format (inline) — password.txt:::30"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash hashcat format (single-quoted) — password.txt:::30"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" -w ${TEST_FILES_DIR}/password.txt:::PostgreSQL Hash hashcat format (double-quoted) — password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt:::MSSQL Hash — password.txt:::30"

    # ── JWT — Medium ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt:::JWT HS256 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt:::JWT HS384 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt:::JWT HS512 — password.txt:::60"

    # ── Network / Infra ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt:::Ansible Vault — password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt:::Cisco Type 5 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt:::Cisco Type 8 — password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt:::Cisco Type 9 — password.txt:::180"

    # ── Kerberos — Medium ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt:::Kerberos TGS-RC4 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt:::Kerberos AS-REP-RC4 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt:::Kerberos TGS-AES128 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt:::Kerberos TGS-AES256 — password.txt:::60"

    # ── NetNTLM — Medium ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt:::NetNTLMv1 — password.txt:::60"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt:::NetNTLMv2 — password.txt:::60"

    # ── DCC ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt:::DCC v1 — password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt:::DCC v2 — password.txt:::180"

    # ── DPAPI — Very Slow ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt:::DPAPI v1 — password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt:::DPAPI v2 — password.txt:::180"

    # ── Wireless — Medium ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt:::WPA Handshake — password.txt:::60"

    # ── Archives — Slow ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt:::ZIP Archive — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt:::7-Zip Archive — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt:::RAR Archive — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt:::PDF Document — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt:::ODT Document — password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt:::Office DOCX — password.txt:::120"

    # ── Password Managers — Slow ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt:::KeePass Database — password.txt:::120"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
