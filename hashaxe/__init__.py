# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/__init__.py
#  Package initialization for HASHAXE multi-format password cracker.
#  Exposes main API, version info, and high-level project overview.
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
hashaxe — Multi-Format Password & Passphrase Cracker V1

GANGA Offensive Ops // Bhanu Guragain (Lead Developer / Author)

Highlights:
  • 30+ format handlers: SSH keys, raw hashes, KDFs, archives, databases, tokens
  • 11 attack modes: Wordlist · Mask · PRINCE · Markov · Hybrid · PCFG · AI · OSINT
  • GPU acceleration: CUDA (NVIDIA) + OpenCL (AMD/Intel) — auto-detected
  • Distributed cracking via ZeroMQ with fault-tolerant auto-recovery
  • AI candidate generation (GPT-2 / Markov) + OSINT NLP profiling
  • Auto-Pwn pipeline · REST API · Live TUI · Session resume
  • Quantum bridge (Qiskit) · PQC scanner · SNN · FPGA · Web3/ZK auditing
  • 578 tests · 100% coverage
"""

__version__ = "1.0.0"
__author__ = "Bhanu Guragain (@Bh4nu)"
__license__ = "MIT"

from hashaxe.cracker import hashaxe
from hashaxe.formats import FormatRegistry, FormatTarget

__all__ = ["FormatRegistry", "FormatTarget", "__version__", "hashaxe"]
