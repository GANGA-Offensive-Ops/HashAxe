# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/quantum/qiskit_bridge.py
#  Qiskit Aer GPU-backed quantum simulator bridge for cryptographic operations.
#  Provides real quantum circuit execution via Qiskit, Grover complexity estimation,
#  and honest hardware feasibility assessment.
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
# ⚠️ Version 2.0.0 — Production Audit Upgrade 💀
# ==========================================================================================
"""
quantum/qiskit_bridge.py — Qiskit Aer GPU-backed quantum simulator bridge.

Provides a production-grade interface for:
  1. Quantum circuit construction and execution via Qiskit Aer (GPU + CPU)
  2. Grover's Algorithm complexity estimation with real math
  3. Hardware feasibility assessment with honest labels
  4. Graceful degradation to pure-math estimator when Qiskit is unavailable

Modes of Operation:
  SIMULATOR  — Running real quantum circuits on Qiskit Aer (classical simulation of
                quantum mechanics). This is REAL quantum simulation — the same technology
                IBM uses for circuit development. Outputs are measured from the simulator.
  ESTIMATOR  — Pure mathematical computation of quantum complexity bounds.
                Used when Qiskit is not installed. Outputs are calculated, not simulated.

Feasibility Categories:
  TOY_SIMULATABLE         — Can simulate NOW on your hardware (≤29 qubits on GPU, ≤25 CPU)
  NEAR_TERM_HARDWARE      — Emerging 100–1,000 qubit hardware (Atom Computing 1,180q,
                             IBM Condor 1,121q, Nord Quantique 1,000q self-correcting)
  FAULT_TOLERANT_REQUIRED — Needs millions of physical qubits with full error correction
  BEYOND_CURRENT_TECHNOLOGY — Exceeds all projected near-term hardware

Architecture:
  ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐
  │  GroverOracle │──▶│  QiskitBridge     │──▶│ Aer GPU/CPU  │
  │  (hash POC)  │   │  (circuit mgmt)  │   │ (simulation) │
  └──────────────┘   └──────────────────┘   └──────────────┘

References:
  - IBM Qiskit Documentation (2026)
  - Grover, L.K. "A Fast Quantum Mechanical Algorithm for Database Search" (STOC 1996)
  - Amy et al. (2016) "Estimating the Cost of Generic Quantum Pre-Image Attacks on SHA-2/SHA-3"
  - Atom Computing (2023) — 1,180-qubit neutral atom system
  - IBM (2023) — Condor 1,121-qubit superconducting processor
  - Nord Quantique (2025) — Self-correcting 1,000-qubit design
"""
from __future__ import annotations

import logging
import math
import sys
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────────────


class Feasibility(Enum):
    """Quantum hardware feasibility classification."""

    TOY_SIMULATABLE = "TOY_SIMULATABLE"
    NEAR_TERM_HARDWARE = "NEAR_TERM_HARDWARE"
    FAULT_TOLERANT_REQUIRED = "FAULT_TOLERANT_REQUIRED"
    BEYOND_CURRENT_TECHNOLOGY = "BEYOND_CURRENT_TECHNOLOGY"


# ── Output Models ─────────────────────────────────────────────────────────────


@dataclass
class QuantumBackendInfo:
    """Information about the available quantum simulation backend."""

    name: str = "none"
    gpu_available: bool = False
    max_qubits: int = 0
    vram_mb: int = 0
    simulator_type: str = "none"


@dataclass
class QuantumResult:
    """Result from a quantum circuit execution on Qiskit Aer.

    When executed on Aer, this IS a real quantum simulation — the simulator
    faithfully models quantum mechanical behavior. The ``mode`` field
    distinguishes between actual simulation and pure estimation.
    """

    counts: dict[str, int] = field(default_factory=dict)
    statevector: list[complex] | None = None
    execution_time: float = 0.0
    shots: int = 0
    qubits: int = 0
    backend: str = "none"
    success: bool = False

    # Provenance
    mode: str = "SIMULATOR"  # SIMULATOR when Qiskit runs, ESTIMATOR for math-only
    measured: bool = False  # True = from real hardware, False = from simulator
    simulation: bool = True  # True when running on Aer (classical simulation of QM)
    implementation_status: str = "PRODUCTION"
    result_origin: str = "qiskit_aer_simulation"


@dataclass
class GroverEstimate:
    """Grover's Algorithm complexity estimate for a given keyspace.

    All values are mathematically exact or literature-backed estimates.
    """

    keyspace: int = 0
    classical_ops: int = 0
    quantum_query_complexity: int = 0  # O(√N) queries
    grover_iterations: int = 0  # π/4 × √N optimal iterations
    required_index_qubits: int = 0  # ceil(log2(N)) qubits for the index register
    estimated_oracle_cost: str = ""  # Rough gate complexity for the oracle circuit
    speedup_factor: float = 0.0
    feasibility: Feasibility = Feasibility.BEYOND_CURRENT_TECHNOLOGY
    feasibility_rationale: str = ""

    # Provenance
    mode: str = "ESTIMATOR"
    measured: bool = False
    simulation: bool = False
    implementation_status: str = "PRODUCTION"
    result_origin: str = "mathematical_computation"
    confidence: str = "HIGH"
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    references_basis: list[str] = field(default_factory=list)

    # Backward compatibility
    @property
    def required_qubits(self) -> int:
        """Backward-compatible alias."""
        return self.required_index_qubits


# ══════════════════════════════════════════════════════════════════════════════
# QiskitBridge — Main Bridge Class
# ══════════════════════════════════════════════════════════════════════════════


class QiskitBridge:
    """Bridge between Hashaxe and IBM Qiskit quantum simulation.

    Manages the lifecycle of quantum circuits, backend selection,
    and result interpretation for cryptographic applications.

    When Qiskit is installed:
      - Full quantum circuit construction and simulation
      - GPU-accelerated Aer simulation (NVIDIA VRAM-backed)
      - Real Grover's Algorithm execution on reduced keyspaces

    When Qiskit is NOT installed:
      - Graceful degradation to pure-math estimator mode
      - All complexity estimates remain fully functional
      - No fake simulation results generated

    Usage:
        bridge = QiskitBridge()

        # Check capabilities
        print(bridge.info())

        # Estimate Grover's speedup for any keyspace
        estimate = bridge.estimate_grover_speedup(keyspace=2**40)

        # Run a real quantum circuit (requires Qiskit)
        if bridge.is_available:
            result = bridge.run_circuit(circuit, shots=8192)
    """

    def __init__(self, prefer_gpu: bool = True, max_qubits: int = 29):
        self._prefer_gpu = prefer_gpu
        self._max_qubits = max_qubits
        self._backend = None
        self._qiskit_available = False
        self._backend_info = QuantumBackendInfo()
        self._detect_backend()

    def _detect_backend(self) -> None:
        """Detect the best available Qiskit Aer backend."""
        try:
            import psutil
            from qiskit_aer import AerSimulator  # type: ignore

            self._qiskit_available = True

            # Dynamic RAM Scaling for CPU Max Qubits
            # Statevector scales at 2^N * 16 bytes (complex128).
            try:
                free_ram = psutil.virtual_memory().available
                max_states = free_ram / 16.0
                dynamic_cpu_qubits = int(math.floor(math.log2(max_states))) - 1  # Safety margin
                dynamic_cpu_qubits = min(30, max(10, dynamic_cpu_qubits))
            except Exception:
                dynamic_cpu_qubits = 22  # Hard-capped safe fallback if psutil fails

            # Try GPU backend first
            if self._prefer_gpu:
                try:
                    gpu_sim = AerSimulator(method="statevector", device="GPU")
                    self._backend = gpu_sim
                    self._backend_info = QuantumBackendInfo(
                        name="aer_simulator_gpu",
                        gpu_available=True,
                        max_qubits=self._max_qubits,
                        simulator_type="statevector_gpu",
                    )
                    logger.info("Quantum backend: Aer GPU (statevector)")
                    return
                except Exception:
                    logger.warning(
                        "⚠️  QUANTUM GPU UNAVAILABLE — GPU Aer backend not detected. "
                        "Falling back to CPU Qiskit simulation. "
                        f"Dynamic Qubit Cap Enforced: {dynamic_cpu_qubits} qubits (to prevent memory OOM crashes)."
                    )

            # CPU fallback
            cpu_sim = AerSimulator(method="statevector")
            self._backend = cpu_sim
            self._backend_info = QuantumBackendInfo(
                name="aer_simulator_cpu",
                gpu_available=False,
                max_qubits=min(
                    self._max_qubits, dynamic_cpu_qubits
                ),  # CPU limit scaled dynamically
                simulator_type="statevector_cpu",
            )
            logger.info(
                f"Quantum backend: Aer CPU (statevector). Dynamic OOM Cap: {dynamic_cpu_qubits} qubits."
            )

        except ImportError:
            self._qiskit_available = False
            _msg = (
                "⚠️  QISKIT NOT INSTALLED — Quantum module running in ESTIMATOR mode "
                "(pure math only). No quantum circuits can be executed. "
                "Grover complexity estimates are still accurate (mathematical computation), "
                "but run_circuit() will NOT work. "
                "Install: pip install qiskit qiskit-aer"
            )
            logger.warning(_msg)
            warnings.warn(_msg, stacklevel=2)

    @property
    def is_available(self) -> bool:
        """Check if Qiskit simulation is available."""
        return self._qiskit_available

    @property
    def has_gpu(self) -> bool:
        """Check if GPU-accelerated simulation is available."""
        return self._backend_info.gpu_available

    @property
    def backend_info(self) -> QuantumBackendInfo:
        """Get backend information."""
        return self._backend_info

    @property
    def max_qubits(self) -> int:
        """Maximum simulatable qubits on current backend."""
        return self._backend_info.max_qubits

    @property
    def operating_mode(self) -> str:
        """Current operating mode: SIMULATOR or ESTIMATOR."""
        return "SIMULATOR" if self._qiskit_available else "ESTIMATOR"

    def run_circuit(
        self,
        circuit: Any,
        shots: int = 8192,
        seed: int | None = None,
    ) -> QuantumResult:
        """Execute a quantum circuit on the Aer simulator.

        This runs a REAL quantum simulation — Aer faithfully models quantum
        mechanical behavior using statevector/density matrix methods.

        Args:
            circuit: A Qiskit QuantumCircuit object.
            shots: Number of measurement samples.
            seed: Random seed for reproducibility.

        Returns:
            QuantumResult with measurement counts and provenance metadata.
        """
        if not self._qiskit_available or self._backend is None:
            _msg = (
                "⚠️  QUANTUM CIRCUIT EXECUTION BLOCKED — Qiskit is not installed. "
                "Cannot execute quantum circuits without qiskit-aer. "
                "This call returns an empty result. Install: pip install qiskit qiskit-aer"
            )
            logger.error(_msg)
            return QuantumResult(
                success=False,
                mode="ESTIMATOR",
                simulation=False,
                result_origin="unavailable — qiskit not installed",
            )

        try:
            from qiskit import transpile  # type: ignore

            t_start = time.time()
            transpiled = transpile(circuit, self._backend)
            job = self._backend.run(transpiled, shots=shots, seed_simulator=seed)
            result = job.result()
            elapsed = time.time() - t_start

            counts = result.get_counts()
            if isinstance(counts, list):
                counts = counts[0]

            return QuantumResult(
                counts=dict(counts),
                execution_time=elapsed,
                shots=shots,
                qubits=circuit.num_qubits,
                backend=self._backend_info.name,
                success=True,
                mode="SIMULATOR",
                measured=False,  # Aer simulates, doesn't measure on real QPU
                simulation=True,  # This is quantum simulation on classical hardware
                result_origin="qiskit_aer_simulation",
            )
        except Exception as e:
            logger.error("Quantum circuit execution failed: %s", e)
            return QuantumResult(success=False, result_origin=f"error: {e}")

    def estimate_grover_speedup(self, keyspace: int) -> dict | GroverEstimate:
        """Estimate Grover's algorithm speedup for a given keyspace.

        This is pure mathematics — no simulation required.

        Classical search: O(N) operations
        Grover's search:  O(√N) operations (quadratic speedup)
        Optimal iterations: π/4 × √N

        Args:
            keyspace: Size of the search space (N).

        Returns:
            GroverEstimate with complexity analysis and feasibility assessment.
            Also returns backward-compatible dict for existing callers.
        """
        if keyspace <= 0:
            return {"error": "Invalid keyspace"}

        classical_ops = keyspace
        quantum_query = int(math.ceil(math.sqrt(keyspace)))
        grover_iters = int(math.ceil(math.pi / 4 * math.sqrt(keyspace)))
        required_qubits = int(math.ceil(math.log2(keyspace))) + 1  # +1 for ancilla
        speedup = classical_ops / quantum_query if quantum_query > 0 else 0

        # Oracle cost estimation (rough — depends on hash function complexity)
        if required_qubits <= 10:
            oracle_cost = f"~{required_qubits * 100} gates (toy circuit)"
        elif required_qubits <= 30:
            oracle_cost = f"~{required_qubits * 1000} gates (simulatable oracle)"
        elif required_qubits <= 256:
            oracle_cost = f"~{required_qubits * 10000} gates (hash-aware oracle required)"
        else:
            oracle_cost = f"~{required_qubits * 100000}+ gates (full cryptographic oracle)"

        # Feasibility assessment
        feasibility, rationale = self._assess_feasibility(required_qubits)

        estimate = GroverEstimate(
            keyspace=keyspace,
            classical_ops=classical_ops,
            quantum_query_complexity=quantum_query,
            grover_iterations=grover_iters,
            required_index_qubits=required_qubits,
            estimated_oracle_cost=oracle_cost,
            speedup_factor=round(speedup, 2),
            feasibility=feasibility,
            feasibility_rationale=rationale,
            assumptions=[
                "Assumes ideal error-free quantum computer (logical qubits)",
                "Oracle cost is approximate — actual cost depends on hash function chosen",
                "Grover's algorithm has limited parallelizability (fundamental constraint)",
            ],
            limitations=[
                "Quantum speedup is quadratic (√N), not exponential",
                "Physical qubit overhead for error correction is ~1000-5000× logical qubits",
                "Sequential query requirement limits effective parallelization",
            ],
            references_basis=[
                "Grover, L.K. (1996) STOC",
                "Amy et al. (2016) — SHA-2/SHA-3 oracle cost estimation",
                "Atom Computing (2023) — 1,180 qubit neutral atom system",
                "IBM (2023) — Condor 1,121-qubit processor",
            ],
        )

        # Simulation/estimation warning for operator awareness
        if not self._qiskit_available:
            sim_warning = (
                "⚠️  ESTIMATOR MODE — Qiskit is not installed. These results are "
                "mathematically computed complexity bounds, NOT from quantum circuit "
                "execution. The Grover speedup numbers are exact (math), but no "
                "quantum simulation was run. Install qiskit for circuit execution."
            )
        else:
            sim_warning = ""

        # Return backward-compatible dict format
        # Internal consumers can use the GroverEstimate dataclass directly
        return {
            "keyspace": keyspace,
            "classical_ops": classical_ops,
            "quantum_ops": quantum_query,
            "quantum_query_complexity": quantum_query,
            "grover_iterations": grover_iters,
            "required_qubits": required_qubits,
            "required_index_qubits": required_qubits,
            "estimated_oracle_cost": oracle_cost,
            "speedup_factor": round(speedup, 2),
            "feasibility": feasibility.value,
            "feasibility_rationale": rationale,
            "mode": "ESTIMATOR",
            "measured": False,
            "simulation": False,
            "implementation_status": "PRODUCTION",
            "result_origin": "mathematical_computation",
            "confidence": "HIGH",
            "simulation_warning": sim_warning,
        }

    def estimate_grover_speedup_detailed(self, keyspace: int) -> GroverEstimate:
        """Return a full GroverEstimate dataclass (not a dict).

        For callers that want structured access to all fields.
        """
        raw = self.estimate_grover_speedup(keyspace)
        if isinstance(raw, dict) and "error" in raw:
            return GroverEstimate(keyspace=keyspace)
        # Build from dict
        return GroverEstimate(
            keyspace=raw["keyspace"],
            classical_ops=raw["classical_ops"],
            quantum_query_complexity=raw["quantum_query_complexity"],
            grover_iterations=raw["grover_iterations"],
            required_index_qubits=raw["required_index_qubits"],
            estimated_oracle_cost=raw["estimated_oracle_cost"],
            speedup_factor=raw["speedup_factor"],
            feasibility=Feasibility(raw["feasibility"]),
            feasibility_rationale=raw["feasibility_rationale"],
        )

    def _assess_feasibility(self, required_qubits: int) -> tuple[Feasibility, str]:
        """Assess quantum hardware feasibility for a given qubit requirement.

        Based on the current state of quantum computing hardware (early 2026):
          - Atom Computing: 1,180 qubits (neutral atoms)
          - IBM Condor: 1,121 qubits (superconducting)
          - Nord Quantique: ~1,000 qubits (self-correcting)
          - Google Sycamore: 72 qubits (superconducting)

        However, these are PHYSICAL qubits. Logical (error-corrected) qubit
        counts are dramatically lower — typically 1 logical qubit requires
        ~1,000-5,000 physical qubits with surface code error correction.
        """
        simulatable = self._backend_info.max_qubits if self._qiskit_available else 25

        if required_qubits <= simulatable:
            return (
                Feasibility.TOY_SIMULATABLE,
                f"Can simulate on current hardware ({required_qubits} qubits ≤ "
                f"{simulatable} max simulatable). Qiskit Aer can execute this circuit.",
            )
        elif required_qubits <= 50:
            return (
                Feasibility.NEAR_TERM_HARDWARE,
                f"Requires {required_qubits} logical qubits. Current hardware (1,000+ physical "
                f"qubits) may achieve this with sufficient error correction. "
                f"IBM, Atom Computing, and Nord Quantique are approaching this range.",
            )
        elif required_qubits <= 1000:
            return (
                Feasibility.NEAR_TERM_HARDWARE,
                f"Requires {required_qubits} logical qubits (~{required_qubits * 1000:,}-"
                f"{required_qubits * 5000:,} physical qubits with error correction). "
                f"Within reach of scaling roadmaps for 2028-2032 era hardware.",
            )
        elif required_qubits <= 10000:
            return (
                Feasibility.FAULT_TOLERANT_REQUIRED,
                f"Requires {required_qubits} logical qubits (~{required_qubits * 1000:,}-"
                f"{required_qubits * 5000:,} physical qubits). "
                f"Requires full fault-tolerant quantum computing. Projected post-2032.",
            )
        else:
            return (
                Feasibility.BEYOND_CURRENT_TECHNOLOGY,
                f"Requires {required_qubits} logical qubits (~{required_qubits * 1000:,}+ "
                f"physical qubits). Beyond all currently projected hardware timelines.",
            )

    def info(self) -> dict:
        """Return quantum subsystem information."""
        sim_warning = ""
        if not self._qiskit_available:
            sim_warning = (
                "⚠️  ESTIMATOR MODE — Qiskit is not installed. "
                "Grover complexity estimates work (math-only), but quantum "
                "circuit execution (run_circuit) is NOT available. "
                "Install: pip install qiskit qiskit-aer"
            )
        return {
            "qiskit_available": self.is_available,
            "operating_mode": self.operating_mode,
            "backend": self._backend_info.name,
            "gpu": self._backend_info.gpu_available,
            "max_qubits": self._backend_info.max_qubits,
            "simulator_type": self._backend_info.simulator_type,
            "implementation_status": "PRODUCTION",
            "simulation_warning": sim_warning,
        }
