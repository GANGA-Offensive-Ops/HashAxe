# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/__main__.py
#  Entry point for running hashaxe as a Python module (python -m hashaxe).
#  Delegates to cli.main() for argument parsing and dispatch.
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
hashaxe/__main__.py — Enable running as: python -m hashaxe

Usage:
    python -m hashaxe -k id_ed25519 -w rockyou.txt
    python -m hashaxe --help
"""

from hashaxe.cli import main

if __name__ == "__main__":
    main()
