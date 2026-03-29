#!/bin/bash

# =============================================================================
# Hashaxe V4 - MASK ATTACKS Test Suite
# =============================================================================
# Description: Tests all --mask mode commands with targeted masks, pure masks,
#              custom charsets, and uppercase+digit patterns across all hash types.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_4_mask_attack.sh
#   ./file_4_mask_attack.sh --resume 50
#   ./file_4_mask_attack.sh --dry-run
#   ./file_4_mask_attack.sh --timeout 160
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="MASK ATTACKS"
DEFAULT_TIMEOUT=360

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL, MSSQL) → 120s
#   Medium hashes (JWT, Cisco 5, Kerberos, NetNTLM, SSH keys) → 160s
#   Slow  hashes (bcrypt-4, md5crypt, descrypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 360s
#
# Mask attack categories:
#   1. Targeted masks (known pattern + placeholders)
#   2. Pure mask 8 lowercase (?l?l?l?l?l?l?l?l = 208B candidates)
#   3. Custom charset 9-char (?1?1?1?1?1?1?1?1?1 -1 ?l?d = 10T candidates)
#   4. Uppercase + 2 digits (?u?u?u?u?d?d = 676K candidates)
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 1: TARGETED MASK ATTACKS (known pattern + placeholders)
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH Keys ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa --mask 'shadow1?d?d':::SSH OpenSSH Key — mask shadow1?d?d:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk --mask 'Shadow@HTB20?d?d':::SSH PPK Key — mask Shadow@HTB20?d?d:::360"

    # ── MD5 — Fast ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --mask 'passwor?l':::MD5 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mask 'passwor?l':::MD5 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' --mask 'passwor?l':::MD5 Hash (quoted) — mask passwor?l:::120"

    # ── SHA-1 — Fast ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt --mask 'passwor?l':::SHA-1 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --mask 'passwor?l':::SHA-1 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' --mask 'passwor?l':::SHA-1 Hash (quoted) — mask passwor?l:::120"

    # ── SHA-224 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt --mask 'passwor?l':::SHA-224 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01 --mask 'passwor?l':::SHA-224 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash 'd63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01' --mask 'passwor?l':::SHA-224 Hash (quoted) — mask passwor?l:::120"

    # ── SHA-256 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --mask 'passwor?l':::SHA-256 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --mask 'passwor?l':::SHA-256 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' --mask 'passwor?l':::SHA-256 Hash (quoted) — mask passwor?l:::120"

    # ── SHA-384 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt --mask 'passwor?l':::SHA-384 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c5986160c94ce680c47d19c120783a7 --mask 'passwor?l':::SHA-384 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash 'a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c5986160c94ce680c47d19c120783a7' --mask 'passwor?l':::SHA-384 Hash (quoted) — mask passwor?l:::120"

    # ── SHA-512 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --mask 'passwor?l':::SHA-512 Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 --mask 'passwor?l':::SHA-512 Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86' --mask 'passwor?l':::SHA-512 Hash (quoted) — mask passwor?l:::120"

    # ── NTLM — Fast ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --mask 'passwor?l':::NTLM Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c --mask 'passwor?l':::NTLM Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' --mask 'passwor?l':::NTLM Hash (quoted) — mask passwor?l:::120"

    # ── LM — Fast (Legacy Windows) ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt --mask 'PASSWO?u':::LM Hash — mask PASSWO?u:::120"
    "python3 -m hashaxe --hash e52cac67419a9a224a3b108f3fa6cb6d --mask 'PASSWO?u':::LM Hash (inline) — mask PASSWO?u:::120"

    # ── bcrypt — Slow/Very-Slow ───────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --mask 'shadow1?d?d':::bcrypt cost-4 — mask shadow1?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --mask 'Shadow@HTB20?d?d':::bcrypt cost-10 — mask Shadow@HTB20?d?d:::360"

    # ── Memory-Hard KDFs — Very Slow ─────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt --mask 'hashca?l':::Argon2id — mask hashca?l:::360"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt --mask 'hashca?l':::scrypt — mask hashca?l:::360"

    # ── Unix Crypt — Medium/Slow ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt --mask 'shadow1?d?d':::md5crypt — mask shadow1?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt --mask 'Shadow@HTB20?d?d':::sha256crypt — mask Shadow@HTB20?d?d:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --mask 'Shadow@HTB20?d?d':::sha512crypt — mask Shadow@HTB20?d?d:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt --mask 'hashca?l':::descrypt — mask hashca?l:::120"

    # ── Database Hashes — Fast ───────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt --mask 'passwor?l':::MySQL Hash — mask passwor?l:::120"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' --mask 'passwor?l':::MySQL Hash (inline) — mask passwor?l:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --mask 'hashca?l':::PostgreSQL Hash hashcat — mask hashca?l:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --mask 'hashca?l':::PostgreSQL Hash john — mask hashca?l:::120"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d --mask 'hashca?l':::PostgreSQL Hash john format (inline) — mask hashca?l:::120"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' --mask 'hashca?l':::PostgreSQL Hash john format (single-quoted) — mask hashca?l:::120"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" --mask 'hashca?l':::PostgreSQL Hash john format (double-quoted) — mask hashca?l:::120"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin --mask 'hashca?l':::PostgreSQL Hash hashcat format (inline) — mask hashca?l:::120"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' --mask 'hashca?l':::PostgreSQL Hash hashcat format (single-quoted) — mask hashca?l:::120"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" --mask 'hashca?l':::PostgreSQL Hash hashcat format (double-quoted) — mask hashca?l:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt --mask 'passwor?l':::MSSQL Hash — mask passwor?l:::120"

    # ── JWT — Medium ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt --mask 'passwor?l':::JWT HS256 — mask passwor?l:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt --mask 'passwor?l':::JWT HS384 — mask passwor?l:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt --mask 'passwor?l':::JWT HS512 — mask passwor?l:::160"

    # ── Network / Infra ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt --mask 'passwor?l':::Ansible Vault — mask passwor?l:::360"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --mask 'shadow1?d?d':::Cisco Type 5 — mask shadow1?d?d:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --mask 'hashca?l':::Cisco Type 8 — mask hashca?l:::360"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --mask 'hashca?l':::Cisco Type 9 — mask hashca?l:::360"

    # ── Kerberos — Medium ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --mask 'passwor?l':::Kerberos TGS-RC4 — mask passwor?l:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --mask 'passwor?l':::Kerberos AS-REP-RC4 — mask passwor?l:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt --mask 'Shadow@HTB20?d?d':::Kerberos TGS-AES128 — mask Shadow@HTB20?d?d:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --mask 'Shadow@HTB20?d?d':::Kerberos TGS-AES256 — mask Shadow@HTB20?d?d:::160"

    # ── NetNTLM — Medium ──────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --mask 'hashca?l':::NetNTLMv1 — mask hashca?l:::160"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --mask 'passwor?l':::NetNTLMv2 — mask passwor?l:::160"

    # ── DCC ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt --mask 'passwor?l':::DCC v1 — mask passwor?l:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt --mask 'Shadow@HTB20?d?d':::DCC v2 — mask Shadow@HTB20?d?d:::360"

    # ── DPAPI — Very Slow ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --mask 'Shadow@HTB20?d?d':::DPAPI v1 — mask Shadow@HTB20?d?d:::360"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --mask 'Shadow@HTB20?d?d':::DPAPI v2 — mask Shadow@HTB20?d?d:::360"

    # ── Wireless — Medium ─────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --mask 'Shadow@HTB20?d?d':::WPA Handshake — mask Shadow@HTB20?d?d:::120"

    # ── Archives — Slow ───────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip --mask 'Shadow@HTB20?d?d':::ZIP Archive — mask Shadow@HTB20?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z --mask 'Shadow@HTB20?d?d':::7-Zip Archive — mask Shadow@HTB20?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar --mask 'Shadow@HTB20?d?d':::RAR Archive — mask Shadow@HTB20?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf --mask 'shadow?d?d?d':::PDF Document — mask shadow?d?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt --mask 'shadow?d?d?d':::ODT Document — mask shadow?d?d?d:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx --mask 'shadow?d?d?d':::Office DOCX — mask shadow?d?d?d:::120"

    # ── Password Managers — Slow ──────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx --mask 'Shadow@HTB20?d?d':::KeePass Database — mask Shadow@HTB20?d?d:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 2: PURE MASK 8 LOWERCASE (?l?l?l?l?l?l?l?l = 208B candidates)
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 — Fast ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt --mask '?l?l?l?l?l?l?l?l':::MD5 Hash — pure mask 8l:::120"

    # ── SHA-1 — Fast ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt --mask '?l?l?l?l?l?l?l?l':::SHA-1 Hash — pure mask 8l:::120"

    # ── SHA-224 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt --mask '?l?l?l?l?l?l?l?l':::SHA-224 Hash — pure mask 8l:::120"

    # ── SHA-256 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt --mask '?l?l?l?l?l?l?l?l':::SHA-256 Hash — pure mask 8l:::120"

    # ── SHA-384 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt --mask '?l?l?l?l?l?l?l?l':::SHA-384 Hash — pure mask 8l:::120"

    # ── SHA-512 — Fast ────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt --mask '?l?l?l?l?l?l?l?l':::SHA-512 Hash — pure mask 8l:::120"
 
    # ── NTLM — Fast ───────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt --mask '?l?l?l?l?l?l?l?l':::NTLM Hash — pure mask 8l:::180"
 
    # ── bcrypt — Slow ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt --mask '?l?l?l?l?l?l?d?d?d':::bcrypt cost-4 — mask 6l+3d:::2500"


    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt --mask '?l?l?l?l?l?l?l':::PostgreSQL Hash john — pure mask 7l:::360"

    "python3 -m hashaxe --hash a8dd1a70bd4598e612bb25a000367da5 --mask '?u?l?l?l?s?d?d?d?d':::MD5 Hash — mask ?u?l?l?l?s?d?d?d?d:::100000"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
