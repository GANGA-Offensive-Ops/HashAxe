# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/distributed/__init__.py
#  Linear-scale distributed cracking across multiple machines via ZeroMQ.
#  Master/worker architecture with fault-tolerant auto-recovery and healing.
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
distributed/ — Linear-scale distributed cracking across multiple machines.

Architecture: ZeroMQ PUSH/PULL for work dispatch, PUB/SUB for control signals.
Scaling: N workers = N× throughput (fully embarrassingly parallel).

Quick start:
    # Master (has the key + wordlist)
    hashaxe -k id_ed25519 -w rockyou.txt --distributed-master

    # Worker(s) — any machine on the same network
    hashaxe --distributed-worker --master 192.168.1.10

    # AWS G5 auto-deploy (see docs/DISTRIBUTED.md)
    hashaxe --deploy-aws --workers 4 --instance g5.xlarge
"""

from hashaxe.distributed.master import MasterNode, WorkItem, WorkResult
from hashaxe.distributed.worker import WorkerNode

__all__ = ["MasterNode", "WorkItem", "WorkResult", "WorkerNode"]
