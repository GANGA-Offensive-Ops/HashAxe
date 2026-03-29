#!/bin/bash

# =============================================================================
# Hashaxe V4 - RULES ATTACKS Test Suite
# =============================================================================
# Description: Tests all --rules and --rule-file mode commands with wordlist-based
#              rule transformations across all supported hash types.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0
# Date: March 2026
#
# Usage:
#   ./file_5_rules_attack.sh
#   ./file_5_rules_attack.sh --resume 20
#   ./file_5_rules_attack.sh --dry-run
#   ./file_5_rules_attack.sh --timeout 180
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILES_DIR="${SCRIPT_DIR}/../test_files"
source "${SCRIPT_DIR}/hashaxe_lib.sh" || {
    echo "ERROR: Cannot source hashaxe_lib.sh from ${SCRIPT_DIR}" >&2
    exit 1
}

SUITE_NAME="RULES ATTACKS"
DEFAULT_TIMEOUT=180

# =============================================================================
# COMMAND LIST
# Format: "command:::description:::timeout_seconds"
#
# Timeout tiers used:
#   Fast  hashes (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL, MSSQL) → 30s
#   Medium hashes (JWT, Cisco 5, Kerberos, NetNTLM, SSH keys) → 60s
#   Slow  hashes (bcrypt-4, md5crypt, descrypt, Archives, WPA, KeePass) → 120s
#   Very slow (bcrypt-10, Argon2id, scrypt, Ansible, Cisco 8/9, DCC2, DPAPI) → 180s
#
# Rules attack modes:
#   --rules         = Apply built-in rule transformations
#   --rule-file     = Apply custom rule file (best66.rule)
#   --no-smart-order = Disable smart ordering
# =============================================================================
declare -a COMMANDS=(

    # ═════════════════════════════════════════════════════════════════════════
    # SSH KEYS
    # ═════════════════════════════════════════════════════════════════════════

    # ── SSH OpenSSH Key (password: xr7kQ2m123) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules:::SSH OpenSSH Key — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SSH OpenSSH Key — best66.rule:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_id_rsa -w ${TEST_FILES_DIR}/password.txt --rules --no-smart-order:::SSH OpenSSH Key — rules no-smart-order:::180"

    # ── SSH PPK Key (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --rules:::SSH PPK Key — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_key.ppk -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SSH PPK Key — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # FAST HASHES (MD5, SHA-*, NTLM, DCC1, MySQL, PostgreSQL, MSSQL)
    # ═════════════════════════════════════════════════════════════════════════

    # ── MD5 Hash (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::MD5 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::MD5 Hash — best66.rule:::30"
    "python3 -m hashaxe --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w ${TEST_FILES_DIR}/password.txt --rules:::MD5 Hash (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w ${TEST_FILES_DIR}/password.txt --rules:::MD5 Hash (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"5f4dcc3b5aa765d61d8327deb882cf99\" -w ${TEST_FILES_DIR}/password.txt --rules:::MD5 Hash (double-quoted) — rules password.txt:::30"

    # ── SHA-1 Hash (password: password) ──────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-1 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha1.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SHA-1 Hash — best66.rule:::30"
    "python3 -m hashaxe --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-1 Hash (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-1 Hash (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\" -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-1 Hash (double-quoted) — rules password.txt:::30"

    # ── SHA-224 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-224 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha224.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SHA-224 Hash — best66.rule:::30"

    # ── SHA-256 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-256 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SHA-256 Hash — best66.rule:::30"

    # ── SHA-384 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-384 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha384.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SHA-384 Hash — best66.rule:::30"

    # ── SHA-512 Hash (password: password) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --rules:::SHA-512 Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::SHA-512 Hash — best66.rule:::30"

    # ── NTLM Hash (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::NTLM Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ntlm_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::NTLM Hash — best66.rule:::30"
    "python3 -m hashaxe --hash 8846f7eaee8fb117ad06bdd830b7586c -w ${TEST_FILES_DIR}/password.txt --rules:::NTLM Hash (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash '8846f7eaee8fb117ad06bdd830b7586c' -w ${TEST_FILES_DIR}/password.txt --rules:::NTLM Hash (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"8846f7eaee8fb117ad06bdd830b7586c\" -w ${TEST_FILES_DIR}/password.txt --rules:::NTLM Hash (double-quoted) — rules password.txt:::30"

    # ── LM Hash (password: PASSWORD) ──────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::LM Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/lm_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::LM Hash — best66.rule:::30"

    # ── MySQL Native Password (password: password) ────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::MySQL Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mysql_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::MySQL Hash — best66.rule:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt --rules:::MySQL Hash (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' -w ${TEST_FILES_DIR}/password.txt --rules:::MySQL Hash (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19\" -w ${TEST_FILES_DIR}/password.txt --rules:::MySQL Hash (double-quoted) — rules password.txt:::30"

    # ── PostgreSQL MD5 (password: password) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash hashcat — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_hashcat.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::PostgreSQL Hash hashcat — best66.rule:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash john — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/postgres_hash_john.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::PostgreSQL Hash john — best66.rule:::30"
    "python3 -m hashaxe --hash admin:md50a245ea64f49f9aa79fa9c79bbd95c8d -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash john format (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash 'admin:md50a245ea64f49f9aa79fa9c79bbd95c8d' -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash john format (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"admin:md50a245ea64f49f9aa79fa9c79bbd95c8d\" -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash john format (double-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash 0a245ea64f49f9aa79fa9c79bbd95c8d:admin -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash hashcat format (inline) — rules password.txt:::30"
    "python3 -m hashaxe --hash '0a245ea64f49f9aa79fa9c79bbd95c8d:admin' -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash hashcat format (single-quoted) — rules password.txt:::30"
    "python3 -m hashaxe --hash \"0a245ea64f49f9aa79fa9c79bbd95c8d:admin\" -w ${TEST_FILES_DIR}/password.txt --rules:::PostgreSQL Hash hashcat format (double-quoted) — rules password.txt:::30"

    # ── MSSQL 2012+ (password: password) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::MSSQL Hash — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/mssql_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::MSSQL Hash — best66.rule:::30"

    # ═════════════════════════════════════════════════════════════════════════
    # SLOW HASHES (bcrypt-4, md5crypt, descrypt)
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt Cost 4 (password: xr7kQ2m123) ───────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::bcrypt cost-4 — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost4_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::bcrypt cost-4 — best66.rule:::120"

    # ── md5crypt (password: xr7kQ2m123) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::md5crypt — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/md5crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::md5crypt — best66.rule:::120"

    # ── DES Crypt (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::descrypt — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/descrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::descrypt — best66.rule:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # VERY SLOW HASHES (bcrypt-10, Argon2id, scrypt, sha-crypt, Ansible, Cisco 8/9, DCC2, DPAPI)
    # ═════════════════════════════════════════════════════════════════════════

    # ── bcrypt Cost 10 (password: Shadow@HTB2026) ─────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::bcrypt cost-10 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/bcrypt_cost10_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::bcrypt cost-10 — best66.rule:::180"

    # ── Argon2id (password: Shadow@HTB2026) ───────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Argon2id — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/argon2id_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Argon2id — best66.rule:::180"

    # ── scrypt (password: Shadow@HTB2026) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::scrypt — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/scrypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::scrypt — best66.rule:::180"

    # ── sha256crypt (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::sha256crypt — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha256crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::sha256crypt — best66.rule:::180"

    # ── sha512crypt (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::sha512crypt — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/sha512crypt_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::sha512crypt — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # JWT (Medium)
    # ═════════════════════════════════════════════════════════════════════════

    # ── JWT HS256 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --rules:::JWT HS256 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs256.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::JWT HS256 — best66.rule:::180"

    # ── JWT HS384 (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --rules:::JWT HS384 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs384.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::JWT HS384 — best66.rule:::180"

    # ── JWT HS512 (password: password) ───────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --rules:::JWT HS512 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/jwt_hs512.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::JWT HS512 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # NETWORK / INFRA
    # ═════════════════════════════════════════════════════════════════════════

    # ── Ansible Vault (password: Shadow@HTB2026) ──────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Ansible Vault — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/ansible_vault.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Ansible Vault — best66.rule:::180"

    # ── Cisco Type 5 (password: xr7kQ2m123) ────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Cisco Type 5 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type5_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Cisco Type 5 — best66.rule:::180"

    # ── Cisco Type 8 (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Cisco Type 8 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type8_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Cisco Type 8 — best66.rule:::180"

    # ── Cisco Type 9 (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Cisco Type 9 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/cisco_type9_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Cisco Type 9 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # KERBEROS
    # ═════════════════════════════════════════════════════════════════════════

    # ── Kerberoast TGS-REP RC4 (password: password) ──────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Kerberos TGS-RC4 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_rc4.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Kerberos TGS-RC4 — best66.rule:::180"

    # ── AS-REP Roast RC4 (password: password) ─────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Kerberos AS-REP-RC4 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_asrep_rc4.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Kerberos AS-REP-RC4 — best66.rule:::180"

    # ── Kerberos TGS AES128 (password: Shadow@HTB2026) ────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Kerberos TGS-AES128 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes128.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Kerberos TGS-AES128 — best66.rule:::180"

    # ── Kerberos TGS AES256 (password: Shadow@HTB2026) ────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --rules:::Kerberos TGS-AES256 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/kerberos_tgs_aes256.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Kerberos TGS-AES256 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # NETNTLM
    # ═════════════════════════════════════════════════════════════════════════

    # ── NetNTLMv1 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::NetNTLMv1 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::NetNTLMv1 — best66.rule:::180"

    # ── NetNTLMv2 (password: password) ────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::NetNTLMv2 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/netntlmv2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::NetNTLMv2 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DCC (Domain Cached Credentials)
    # ═════════════════════════════════════════════════════════════════════════

    # ── DCC v1 (password: password) ───────────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::DCC v1 — rules password.txt:::30"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::DCC v1 — best66.rule:::30"

    # ── DCC v2 (password: Shadow@HTB2026) ─────────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::DCC v2 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dcc2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::DCC v2 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # DPAPI
    # ═════════════════════════════════════════════════════════════════════════

    # ── DPAPI v1 (password: Shadow@HTB2026) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::DPAPI v1 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v1_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::DPAPI v1 — best66.rule:::180"

    # ── DPAPI v2 (password: Shadow@HTB2026) ──────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rules:::DPAPI v2 — rules password.txt:::180"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/dpapi_v2_hash.txt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::DPAPI v2 — best66.rule:::180"

    # ═════════════════════════════════════════════════════════════════════════
    # WIRELESS
    # ═════════════════════════════════════════════════════════════════════════

    # ── WPA Handshake (password: Shadow@HTB2026) ──────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --rules:::WPA Handshake — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/wpa_handshake.hccapx -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::WPA Handshake — best66.rule:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # ARCHIVES
    # ═════════════════════════════════════════════════════════════════════════

    # ── ZIP Archive (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --rules:::ZIP Archive — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.zip -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::ZIP Archive — best66.rule:::120"

    # ── 7-Zip Archive (password: Shadow@HTB2026) ──────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --rules:::7-Zip Archive — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.7z -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::7-Zip Archive — best66.rule:::120"

    # ── RAR Archive (password: Shadow@HTB2026) ────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --rules:::RAR Archive — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.rar -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::RAR Archive — best66.rule:::120"

    # ── PDF Document (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --rules:::PDF Document — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.pdf -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::PDF Document — best66.rule:::120"

    # ── ODF Document (password: Shadow@HTB2026) ───────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --rules:::ODT Document — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.odt -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::ODT Document — best66.rule:::120"

    # ── Office DOCX (password: Shadow@HTB2026) ─────────────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --rules:::Office DOCX — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test_encrypted.docx -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::Office DOCX — best66.rule:::120"

    # ═════════════════════════════════════════════════════════════════════════
    # PASSWORD MANAGERS
    # ═════════════════════════════════════════════════════════════════════════

    # ── KeePass Database (password: Shadow@HTB2026) ───────────────────────────
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --rules:::KeePass Database — rules password.txt:::120"
    "python3 -m hashaxe -k ${TEST_FILES_DIR}/test.kdbx -w ${TEST_FILES_DIR}/password.txt --rule-file /usr/share/hashcat/rules/best66.rule:::KeePass Database — best66.rule:::120"
)

# =============================================================================
# Entry Point
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_suite "$@"
    exit $?
fi
