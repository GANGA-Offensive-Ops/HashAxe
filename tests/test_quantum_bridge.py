# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_quantum_bridge.py
#  Comprehensive pytest suite for the Quantum Bridge module.
#  Validates Grover math, feasibility labels, graceful degradation, Qiskit integration.
#
# ⚠️ Version 2.0.0 — Production Audit Tests 💀
# ==========================================================================================
"""
tests/test_quantum_bridge.py — Full test suite for hashaxe.quantum.qiskit_bridge.

Tests cover:
  - Grover complexity math correctness
  - Feasibility classification
  - Backend detection and degradation
  - Provenance field correctness
  - Backward compatibility
  - Circuit execution (when Qiskit is available)
  - Edge cases (zero/one keyspace)
"""
from __future__ import annotations

import math

import pytest


class TestGroverMath:
    """Test mathematical correctness of Grover estimates."""

    def test_sqrt_speedup(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=256)
        assert result["classical_ops"] == 256
        assert result["quantum_ops"] == 16  # ceil(√256) = 16
        assert result["speedup_factor"] == 16.0

    def test_grover_iterations(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=256)
        # Optimal: π/4 × √256 = π/4 × 16 ≈ 12.57 → ceil = 13
        expected = int(math.ceil(math.pi / 4 * math.sqrt(256)))
        assert result["grover_iterations"] == expected

    def test_qubit_count(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=256)
        # ceil(log2(256)) + 1 = 8 + 1 = 9
        assert result["required_qubits"] == 9

    def test_large_keyspace(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=2**40)
        assert result["speedup_factor"] > 1_000_000
        assert result["required_qubits"] == 41

    def test_power_of_two(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        for n in [4, 8, 16, 64, 1024]:
            result = bridge.estimate_grover_speedup(keyspace=n)
            sqrt_n = int(math.ceil(math.sqrt(n)))
            assert result["quantum_ops"] == sqrt_n

    def test_zero_keyspace(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=0)
        assert "error" in result

    def test_negative_keyspace(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=-1)
        assert "error" in result

    def test_keyspace_one(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1)
        assert result["classical_ops"] == 1
        assert result["quantum_ops"] == 1
        assert result["speedup_factor"] == 1.0


class TestFeasibility:
    """Test feasibility classification honesty."""

    def test_toy_simulatable(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        # keyspace=16 → 5 qubits → should be TOY_SIMULATABLE
        result = bridge.estimate_grover_speedup(keyspace=16)
        assert result["feasibility"] == "TOY_SIMULATABLE"

    def test_large_keyspace_not_toy(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        # 2^128 → 129 qubits → NOT toy simulatable
        result = bridge.estimate_grover_speedup(keyspace=2**128)
        assert result["feasibility"] != "TOY_SIMULATABLE"

    def test_sha256_near_term_hardware(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        # SHA-256 pre-image → 2^256 keyspace → 257 INDEX qubits
        # 257 logical qubits falls in NEAR_TERM_HARDWARE range (≤1000)
        # Note: full oracle cost would push into FAULT_TOLERANT, but this
        # estimates index register qubits only — the oracle_cost field
        # provides the full gate complexity information separately.
        result = bridge.estimate_grover_speedup(keyspace=2**256)
        assert result["feasibility"] in ("NEAR_TERM_HARDWARE", "FAULT_TOLERANT_REQUIRED")

    def test_feasibility_rationale_populated(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=2**40)
        assert len(result["feasibility_rationale"]) > 0


class TestProvenance:
    """Test provenance and labeling correctness."""

    def test_estimator_mode(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["mode"] == "ESTIMATOR"

    def test_measured_false_for_estimation(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["measured"] is False

    def test_simulation_false_for_estimation(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["simulation"] is False

    def test_implementation_status(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["implementation_status"] == "PRODUCTION"

    def test_result_origin(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["result_origin"] == "mathematical_computation"

    def test_confidence_high(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=1024)
        assert result["confidence"] == "HIGH"


class TestBackendDetection:
    """Test backend detection and graceful degradation."""

    def test_info_structure(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        info = bridge.info()
        assert "qiskit_available" in info
        assert "operating_mode" in info
        assert "backend" in info
        assert "gpu" in info
        assert "max_qubits" in info
        assert "implementation_status" in info
        assert info["implementation_status"] == "PRODUCTION"

    def test_operating_mode(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        info = bridge.info()
        if bridge.is_available:
            assert info["operating_mode"] == "SIMULATOR"
        else:
            assert info["operating_mode"] == "ESTIMATOR"

    def test_estimation_works_without_qiskit(self):
        """Estimation should work regardless of Qiskit availability."""
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=2**20)
        assert "error" not in result
        assert result["speedup_factor"] > 1.0


class TestBackendInfoDataclass:
    """Test the QuantumBackendInfo dataclass."""

    def test_defaults(self):
        from hashaxe.quantum.qiskit_bridge import QuantumBackendInfo

        info = QuantumBackendInfo()
        assert info.name == "none"
        assert info.max_qubits == 0
        assert info.gpu_available is False

    def test_custom_values(self):
        from hashaxe.quantum.qiskit_bridge import QuantumBackendInfo

        info = QuantumBackendInfo(name="test_backend", max_qubits=20, gpu_available=True)
        assert info.name == "test_backend"
        assert info.max_qubits == 20
        assert info.gpu_available is True


class TestGroverEstimateDataclass:
    """Test the GroverEstimate dataclass directly."""

    def test_detailed_estimate(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        est = bridge.estimate_grover_speedup_detailed(keyspace=256)
        assert est.keyspace == 256
        assert est.classical_ops == 256
        assert est.quantum_query_complexity == 16
        assert est.speedup_factor == 16.0

    def test_backward_compat_required_qubits(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        est = bridge.estimate_grover_speedup_detailed(keyspace=256)
        assert est.required_qubits == est.required_index_qubits


class TestOracleCost:
    """Test oracle cost estimation strings."""

    def test_toy_oracle(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=16)
        assert "toy" in result["estimated_oracle_cost"].lower()

    def test_hash_oracle(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=2**128)
        assert (
            "hash" in result["estimated_oracle_cost"].lower()
            or "crypto" in result["estimated_oracle_cost"].lower()
        )


class TestBackwardCompatibility:
    """Test backward compatibility with existing code."""

    def test_dict_return_format(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        result = bridge.estimate_grover_speedup(keyspace=256)
        # Must return dict for existing callers
        assert isinstance(result, dict)
        assert "classical_ops" in result
        assert "quantum_ops" in result
        assert "required_qubits" in result
        assert "speedup_factor" in result
        assert "feasibility" in result

    def test_existing_test_compat_speedup_small(self):
        """Exact replicate of test_v4_advanced.py::TestQiskitBridge::test_grover_speedup_small."""
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge()
        result = bridge.estimate_grover_speedup(keyspace=256)
        assert result["classical_ops"] == 256
        assert result["quantum_ops"] == 16
        assert result["speedup_factor"] == 16.0
        assert result["required_qubits"] == 9
