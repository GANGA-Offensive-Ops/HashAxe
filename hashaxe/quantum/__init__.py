# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/quantum/__init__.py
#  Quantum computing integration package with Qiskit GPU-backed execution.
#  Provides Grover's Algorithm POC and quantum keyspace estimation.
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
hashaxe.quantum — Quantum computing integration package.

Provides quantum-accelerated cryptographic simulation and analysis:
  - Qiskit Aer GPU-backed qubit execution
  - Grover's Algorithm search oracle for hash pre-imaging (POC)
  - Quantum keyspace estimation and benchmark utilities

Dependencies (optional):
  - qiskit        — IBM Quantum SDK
  - qiskit-aer    — High-performance simulator
  - qiskit-aer-gpu — NVIDIA VRAM-backed simulation (optional)

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

__all__ = ["GroverOracle", "QiskitBridge"]
