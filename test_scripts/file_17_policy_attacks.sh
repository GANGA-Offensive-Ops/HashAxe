#!/bin/bash

# =============================================================================
# Hashaxe V4 - POLICY ATTACKS Test Suite
# =============================================================================
# Description: Tests all policy-constrained password attack commands
#              across all 43 format handlers.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_19_policy_attacks.sh
#   ./file_19_policy_attacks.sh --resume 20
#   ./file_19_policy_attacks.sh --dry-run
#   ./file_19_policy_attacks.sh --timeout 60
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="POLICY ATTACKS"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Policy attack mode:
#   --attack policy      = Enable policy-constrained attack
#   --policy <rules>     = Policy rules (len>=8,upper,digit,symbol)
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (SSH keys, JWT, Kerberos RC4, NetNTLM, Cisco 5) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SSH PRIVATE KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── OpenSSH Keys ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_id_rsa --attack policy --policy 'len>=4,lower':::SSH OpenSSH Key — policy 8+ upper digit:::60"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_id_rsa --attack policy --policy 'len>=4,lower':::SSH OpenSSH Key — policy 10+ all:::60"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --attack policy --policy 'len>=4,lower':::SSH OpenSSH Key — policy wordlist:::60"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_id_rsa --attack policy --policy 'len>=4,lower' --gpu:::SSH OpenSSH Key — policy GPU:::60"

    # ── PuTTY PPK Keys ────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_key.ppk --attack policy --policy 'len>=4,lower':::SSH PPK Key — policy 12+ all:::180"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_key.ppk --attack policy --policy 'len>=4,lower' -t 4:::SSH PPK Key — policy 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # RAW HASH DIGESTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt --hash 5f4dcc3b5aa765d61d8327deb882cf99 --attack policy --policy 'len>=4,lower':::MD5 Hash (inline) — policy 8+ upper digit:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=4,lower':::MD5 Hash — policy 8+ upper lower digit:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --attack policy --policy 'len>=4,lower':::MD5 Hash — policy wordlist:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=4,lower' --gpu:::MD5 Hash — policy GPU:::30"

    # ── SHA-256 ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/sha256.txt --attack policy --policy 'len>=4,lower':::SHA-256 Hash — policy 10+ all:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/sha256.txt --attack policy --policy 'len>=4,lower' --gpu:::SHA-256 Hash — policy GPU:::30"

    # ── NTLM ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/ntlm_hash.txt --attack policy --policy 'len>=4,lower' --gpu:::NTLM Hash — policy GPU:::30"

    # ── LM Hash ───────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/lm_hash.txt --attack policy --policy 'len>=4,lower':::LM Hash — policy 7+ upper:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # MODERN PASSWORD HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --attack policy --policy 'len>=4,lower':::bcrypt cost-10 — policy 10+ all:::180"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::bcrypt cost-10 — policy 8 threads:::180"

    # ── Argon2id ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/argon2id_hash.txt --attack policy --policy 'len>=4,lower' -t 4:::Argon2id — policy 12+ all 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # UNIX CRYPT HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── md5crypt ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5crypt_hash.txt --attack policy --policy 'len>=4,lower':::md5crypt — policy 8+ upper digit:::120"

    # ── sha512crypt ────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/sha512crypt_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::sha512crypt — policy 10+ all 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # DATABASE HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── MySQL ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/mysql_hash.txt --attack policy --policy 'len>=4,lower':::MySQL Hash — policy 8+ upper digit:::30"

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt --attack policy --policy 'len>=4,lower':::PostgreSQL Hash hashcat — policy 10+ all:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/postgres_hash_john.txt --attack policy --policy 'len>=4,lower':::PostgreSQL Hash john — policy 10+ all:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION TOKENS
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/jwt_hs256.txt --attack policy --policy 'len>=4,lower':::JWT HS256 — policy 8+ upper lower digit:::60"

    # ── Ansible Vault ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/ansible_vault.txt --attack policy --policy 'len>=4,lower' -t 4:::Ansible Vault — policy 12+ all 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # CISCO PASSWORD TYPES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Cisco Type 5 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/cisco_type5_hash.txt --attack policy --policy 'len>=4,lower':::Cisco Type 5 — policy 8+ upper digit:::60"

    # ── Cisco Type 8 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/cisco_type8_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::Cisco Type 8 — policy 10+ all 8 threads:::180"

    # ── Cisco Type 9 ──────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/cisco_type9_hash.txt --attack policy --policy 'len>=4,lower' -t 4:::Cisco Type 9 — policy 12+ all 4 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberos TGS-RC4 ──────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt --attack policy --policy 'len>=4,lower':::Kerberos TGS-RC4 — policy 8+ upper digit:::60"

    # ── Kerberos AS-REP-RC4 ────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt --attack policy --policy 'len>=4,lower':::Kerberos AS-REP-RC4 — policy 8+ upper lower digit:::60"

    # ── Kerberos TGS-AES256 ───────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt --attack policy --policy 'len>=4,lower' -t 8:::Kerberos TGS-AES256 — policy 10+ all 8 threads:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM HASHES
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/netntlmv1_hash.txt --attack policy --policy 'len>=4,lower':::NetNTLMv1 — policy 8+ upper digit:::60"

    # ── NetNTLMv2 ─────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/netntlmv2_hash.txt --attack policy --policy 'len>=4,lower':::NetNTLMv2 — policy 8+ upper lower digit:::60"

    # ═════════════════════════════════════════════════════════════════════════
    # WINDOWS CACHED CREDENTIALS (DCC)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC1 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/dcc1_hash.txt --attack policy --policy 'len>=4,lower':::DCC v1 — policy 8+ upper digit:::30"

    # ── DCC2 ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/dcc2_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::DCC v2 — policy 10+ all 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI MASTERKEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::DPAPI v1 — policy 10+ all 8 threads:::180"

    # ── DPAPI v2 ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt --attack policy --policy 'len>=4,lower' -t 8:::DPAPI v2 — policy 12+ all 8 threads:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # WPA/WPA2 HANDSHAKES
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/wpa_handshake.hccapx --attack policy --policy 'len>=4,lower' -t 4:::WPA Handshake — policy 8+ all 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.zip --attack policy --policy 'len>=4,lower' -t 4:::ZIP Archive — policy 10+ all 4 threads:::120"

    # ── 7-Zip ──────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.7z --attack policy --policy 'len>=4,lower' -t 4:::7-Zip Archive — policy 10+ all 4 threads:::120"

    # ── RAR ─────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.rar --attack policy --policy 'len>=4,lower' -t 4:::RAR Archive — policy 10+ all 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ENCRYPTED DOCUMENTS
    # ═════════════════════════════════════════════════════════════════════════

    # ── PDF ────────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.pdf --attack policy --policy 'len>=4,lower' -t 4:::PDF Document — policy 10+ all 4 threads:::120"

    # ── ODF (LibreOffice) ──────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.odt --attack policy --policy 'len>=4,lower' -t 4:::ODT Document — policy 10+ all 4 threads:::120"

    # ── Office DOCX ──────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test_encrypted.docx --attack policy --policy 'len>=4,lower' -t 4:::Office DOCX — policy 10+ all 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGER DATABASES
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass ────────────────────────────────────────────────────────────────
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/test.kdbx --attack policy --policy 'len>=4,lower' -t 4:::KeePass Database — policy 12+ all 4 threads:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ADVANCED OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=4,lower' --session policy_session:::MD5 Hash — policy session:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=4,lower' -q:::MD5 Hash — policy quiet:::30"
    "python3 -m hashaxe -w ${TEST_FILES_DIR}/password.txt -k ${TEST_FILES_DIR}/md5hash.txt --attack policy --policy 'len>=4,lower' -o hashaxeed.txt:::MD5 Hash — policy output file:::30"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
