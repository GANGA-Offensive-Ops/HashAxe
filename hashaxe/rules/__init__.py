# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/rules/__init__.py
#  Passphrase mutation engines with built-in rules and Hashcat .rule file parser.
#  Supports mask attacks with custom charsets and ~100 mutation operations.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
rules/ — Passphrase mutation engines.

  mutations.py  — Built-in rules (~100 mutations: capitalize, leet, suffixes, prefixes)
  hashcat.py    — Full Hashcat .rule file parser (25+ opcodes, Best64 built-in)
  mask.py       — Mask attack engine (?l?u?d?s?a?b and custom charsets ?1-?4)
"""

from hashaxe.rules.hashcat import apply_rules_from_file, get_builtin_rules, load_rule_file
from hashaxe.rules.mask import MaskEngine
from hashaxe.rules.mutations import apply_rules, count_rules

__all__ = [
    # mutations
    "apply_rules",
    "count_rules",
    # hashcat
    "load_rule_file",
    "apply_rules_from_file",
    "get_builtin_rules",
    # mask
    "MaskEngine",
]
