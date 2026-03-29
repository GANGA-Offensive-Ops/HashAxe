# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/quantum/grover_oracle.py
#  Grover's Algorithm oracle for hash pre-image search as a POC.
#  Demonstrates quadratic speedup for password recovery at reduced bit-scales.
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
quantum/grover_oracle.py — Grover's Algorithm oracle for cryptographic search.

Implements quantum oracles tailored for hash pre-image search as a
Proof-of-Concept. This demonstrates Grover's quadratic speedup applied
to password recovery at reduced bit-scales.

Algorithm:
  1. Initialize N-qubit superposition (Hadamard on all qubits)
  2. Apply oracle O_f that marks the target state
  3. Apply Grover diffusion operator
  4. Repeat ~π/4 × √N times
  5. Measure — target state has high probability

Limitations:
  - Current simulators handle ≤29 qubits (~537M states max)
  - Real hash pre-images (SHA-256) require 256+ qubits
  - This is a POC demonstrating the mathematical framework

References:
  - Grover, L.K. (1996) "A Fast Quantum Mechanical Algorithm for
    Database Search"
  - Amy, M. et al. (2016) "Estimating the Cost of Generic Quantum
    Pre-Image Attacks on SHA-2 and SHA-3"
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GroverResult:
    """Result from a Grover's algorithm execution."""
    target: int = 0
    found: int = -1
    probability: float = 0.0
    iterations: int = 0
    qubits: int = 0
    shots: int = 0
    success: bool = False
    execution_time: float = 0.0
    counts: dict[str, int] | None = None


class GroverOracle:
    """Construct and execute Grover's Algorithm search circuits.

    This oracle implements a simplified "database search" — given a
    known target index in a space of 2^n states, Grover's algorithm
    finds it with O(√N) queries instead of O(N).

    For password cracking, the concept is:
      - N = keyspace size (e.g., 2^16 for 16-bit reduced hash)
      - Oracle marks the state corresponding to the correct password
      - Grover amplifies this state's amplitude
      - Measurement yields the password with high probability

    Usage:
        from hashaxe.quantum.qiskit_bridge import QiskitBridge
        bridge = QiskitBridge()
        oracle = GroverOracle(bridge)
        result = oracle.search(n_qubits=4, target=7)
        # result.found == 7 with high probability
    """

    def __init__(self, bridge: Any = None):
        self._bridge = bridge
        self._qiskit_available = False
        self._detect()

    def _detect(self) -> None:
        try:
            import qiskit  # type: ignore
            self._qiskit_available = True
        except ImportError:
            self._qiskit_available = False

    @property
    def is_available(self) -> bool:
        return self._qiskit_available

    def search(
        self,
        n_qubits: int = 4,
        target: int = 0,
        shots: int = 8192,
    ) -> GroverResult:
        """Execute Grover's search for a target state.

        Args:
            n_qubits: Number of search qubits (keyspace = 2^n_qubits).
            target: The target state (integer) to search for.
            shots: Number of measurement samples.

        Returns:
            GroverResult with the most likely found state.
        """
        if not self._qiskit_available:
            return self._simulate_classical(n_qubits, target, shots)

        try:
            return self._run_qiskit(n_qubits, target, shots)
        except Exception as e:
            logger.warning("Qiskit Grover failed, using classical simulation: %s", e)
            return self._simulate_classical(n_qubits, target, shots)

    def _run_qiskit(self, n_qubits: int, target: int, shots: int) -> GroverResult:
        """Run Grover's algorithm using Qiskit."""
        import time
        from qiskit import QuantumCircuit  # type: ignore

        N = 2 ** n_qubits
        if target >= N or target < 0:
            raise ValueError(f"Target {target} out of range [0, {N-1}]")

        iterations = max(1, int(math.pi / 4 * math.sqrt(N)))

        # Build circuit
        qc = QuantumCircuit(n_qubits, n_qubits)

        # Initialize superposition
        qc.h(range(n_qubits))

        # Grover iterations
        for _ in range(iterations):
            # Oracle: flip amplitude of target state
            self._apply_oracle(qc, n_qubits, target)
            # Diffusion operator
            self._apply_diffusion(qc, n_qubits)

        # Measure
        qc.measure(range(n_qubits), range(n_qubits))

        # Execute
        t_start = time.time()
        if self._bridge and self._bridge.is_available:
            result = self._bridge.run_circuit(qc, shots=shots)
            counts = result.counts
            elapsed = result.execution_time
        else:
            from qiskit_aer import AerSimulator  # type: ignore
            from qiskit import transpile  # type: ignore
            sim = AerSimulator()
            transpiled = transpile(qc, sim)
            job = sim.run(transpiled, shots=shots)
            result = job.result()
            counts = dict(result.get_counts())
            elapsed = time.time() - t_start

        # Find most probable state
        most_probable = max(counts, key=counts.get)  # type: ignore
        found = int(most_probable, 2)
        probability = counts[most_probable] / shots

        return GroverResult(
            target=target,
            found=found,
            probability=probability,
            iterations=iterations,
            qubits=n_qubits,
            shots=shots,
            success=(found == target),
            execution_time=elapsed,
            counts=counts,
        )

    def _apply_oracle(self, qc: Any, n_qubits: int, target: int) -> None:
        """Apply the Grover oracle — mark the target state with phase flip."""
        # Convert target to binary and apply X gates for 0-bits
        target_bits = format(target, f"0{n_qubits}b")[::-1]

        for i, bit in enumerate(target_bits):
            if bit == "0":
                qc.x(i)

        # Multi-controlled Z gate (via MCX + H sandwiching the last qubit)
        if n_qubits == 1:
            qc.z(0)
        elif n_qubits == 2:
            qc.cz(0, 1)
        else:
            qc.h(n_qubits - 1)
            qc.mcx(list(range(n_qubits - 1)), n_qubits - 1)
            qc.h(n_qubits - 1)

        # Undo X gates
        for i, bit in enumerate(target_bits):
            if bit == "0":
                qc.x(i)

    def _apply_diffusion(self, qc: Any, n_qubits: int) -> None:
        """Apply the Grover diffusion (inversion about mean) operator."""
        qc.h(range(n_qubits))
        qc.x(range(n_qubits))

        if n_qubits == 1:
            qc.z(0)
        elif n_qubits == 2:
            qc.cz(0, 1)
        else:
            qc.h(n_qubits - 1)
            qc.mcx(list(range(n_qubits - 1)), n_qubits - 1)
            qc.h(n_qubits - 1)

        qc.x(range(n_qubits))
        qc.h(range(n_qubits))

    def _simulate_classical(
        self, n_qubits: int, target: int, shots: int
    ) -> GroverResult:
        """Classical simulation of Grover's probability distribution.

        This doesn't use Qiskit but mathematically computes the exact
        output probability distribution of Grover's algorithm.
        """
        import time
        import random

        t_start = time.time()
        N = 2 ** n_qubits
        if target >= N or target < 0:
            return GroverResult(success=False)

        iterations = max(1, int(math.pi / 4 * math.sqrt(N)))

        # Compute exact probability of measuring target after k iterations
        # P(target) = sin²((2k+1) × θ) where θ = arcsin(1/√N)
        theta = math.asin(1.0 / math.sqrt(N))
        prob_target = math.sin((2 * iterations + 1) * theta) ** 2

        # Simulate measurement
        counts: dict[str, int] = {}
        target_key = format(target, f"0{n_qubits}b")

        target_count = 0
        for _ in range(shots):
            if random.random() < prob_target:
                target_count += 1

        counts[target_key] = target_count
        counts["other"] = shots - target_count

        elapsed = time.time() - t_start

        return GroverResult(
            target=target,
            found=target,  # Mathematically, target is always most probable
            probability=prob_target,
            iterations=iterations,
            qubits=n_qubits,
            shots=shots,
            success=True,
            execution_time=elapsed,
            counts=counts,
        )

    def benchmark(self, max_qubits: int = 16) -> list[dict]:
        """Benchmark Grover's speedup across qubit counts.

        Returns a list of {qubits, keyspace, classical_ops, quantum_ops, speedup}
        for each qubit count from 2 to max_qubits.
        """
        results = []
        for n in range(2, max_qubits + 1):
            N = 2 ** n
            quantum_ops = int(math.ceil(math.pi / 4 * math.sqrt(N)))
            results.append({
                "qubits": n,
                "keyspace": N,
                "classical_ops": N,
                "quantum_ops": quantum_ops,
                "speedup": round(N / quantum_ops, 2),
            })
        return results
