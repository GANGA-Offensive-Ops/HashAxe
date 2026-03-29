# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/pqc/__init__.py
#  Post-Quantum Cryptography vulnerability assessment package.
#  Provides scanner and Harvest-Now-Decrypt-Later risk analysis.
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
hashaxe.pqc — Post-Quantum Cryptography vulnerability assessment package.

Modules:
  scanner       — Main PQC scanner interface
  hndl_analyzer — Harvest-Now-Decrypt-Later risk analysis
"""
from __future__ import annotations

__all__ = ["HNDLAnalyzer", "PQCScanner"]
