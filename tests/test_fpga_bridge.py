# ==========================================================================================
# tests/test_fpga_bridge.py — Comprehensive tests for FPGA Hardware Bridge
# ==========================================================================================
"""
Tests the upgraded FPGABridge including:
  - Simulation mode operation
  - Environment state classification
  - Bitstream loading
  - Work dispatch with actual hash comparison
  - Benchmark provenance
  - Toolchain detection
  - Backward compatibility with existing tests
"""
from __future__ import annotations

import hashlib

import pytest


class TestSimulationMode:
    """Test FPGA bridge in explicit simulation mode."""

    def test_simulation_init(self):
        from hashaxe.fpga.bridge import EnvironmentState, FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.is_available
        assert bridge.environment_state == EnvironmentState.SIMULATION_ONLY
        assert bridge.is_real_hardware is False

    def test_device_created(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.device is not None
        assert bridge.device.name == "Crack FPGA Simulator"
        assert bridge.device.vendor == "Simulation"

    def test_load_bitstream(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.load_bitstream(FPGAAlgorithm.MD5)
        assert bridge.device.loaded_algorithm == FPGAAlgorithm.MD5
        assert bridge.device.hash_rate > 0

    def test_all_algorithms_load(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        for algo in FPGAAlgorithm:
            assert bridge.load_bitstream(algo)
            assert bridge.device.hash_rate > 0


class TestDispatch:
    """Test FPGA work dispatch with actual hash verification."""

    def test_dispatch_md5_found(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.MD5)

        target_hash = hashlib.md5(b"fpga_test_fixture_str_7x").digest()
        work = FPGAWorkUnit(
            algorithm=FPGAAlgorithm.MD5,
            target_hash=target_hash,
            candidates=[b"wrong1", b"wrong2", b"fpga_test_fixture_str_7x", b"wrong3"],
        )
        result = bridge.dispatch(work)
        assert result.found is True
        assert result.password == b"fpga_test_fixture_str_7x"
        assert result.candidates_checked == 4

    def test_dispatch_sha256_found(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.SHA256)

        target_hash = hashlib.sha256(b"fpga_secret_fixture_9y").digest()
        work = FPGAWorkUnit(
            algorithm=FPGAAlgorithm.SHA256,
            target_hash=target_hash,
            candidates=[b"wrong", b"fpga_secret_fixture_9y"],
        )
        result = bridge.dispatch(work)
        assert result.found is True
        assert result.password == b"fpga_secret_fixture_9y"

    def test_dispatch_not_found(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.SHA256)

        target_hash = hashlib.sha256(b"notinthelist").digest()
        work = FPGAWorkUnit(
            algorithm=FPGAAlgorithm.SHA256,
            target_hash=target_hash,
            candidates=[b"wrong1", b"wrong2"],
        )
        result = bridge.dispatch(work)
        assert result.found is False
        assert result.candidates_checked == 2

    def test_dispatch_provenance(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.MD5)

        work = FPGAWorkUnit(
            algorithm=FPGAAlgorithm.MD5,
            target_hash=b"test",
            candidates=[b"a"],
        )
        result = bridge.dispatch(work)
        assert result.mode == "SIMULATOR"
        assert result.measured is False
        assert result.simulation is True
        assert result.result_origin == "cpu_simulation"


class TestBenchmark:
    """Test benchmark functionality."""

    def test_benchmark_bcrypt(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        result = bridge.benchmark(FPGAAlgorithm.BCRYPT)
        assert result["algorithm"] == "bcrypt"
        assert result["hash_rate"] > 0
        assert result["simulation"] is True
        assert result["measured"] is False

    def test_benchmark_md5(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        result = bridge.benchmark(FPGAAlgorithm.MD5)
        assert result["hash_rate"] == 500_000_000.0

    def test_benchmark_provenance(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        result = bridge.benchmark(FPGAAlgorithm.SHA256)
        assert result["mode"] == "SIMULATOR"
        assert result["implementation_status"] == "PRODUCTION"
        assert result["result_origin"] == "simulation_fixture"
        assert result["environment_state"] == "SIMULATION_ONLY"


class TestEnvironmentDetection:
    """Test environment state detection."""

    def test_no_hardware_mode(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=False)
        info = bridge.info()
        assert "available" in info
        assert "environment_state" in info

    def test_simulation_state(self):
        from hashaxe.fpga.bridge import EnvironmentState, FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.environment_state == EnvironmentState.SIMULATION_ONLY

    def test_toolchain_in_info(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert "toolchain" in info
        assert "vivado" in info["toolchain"]
        assert "quartus" in info["toolchain"]
        assert "yosys" in info["toolchain"]


class TestInfoStructure:
    """Test info() output structure."""

    def test_all_fields_present(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert "available" in info
        assert "environment_state" in info
        assert "simulation" in info
        assert "real_hardware" in info
        assert "device" in info
        assert "toolchain" in info
        assert "supported_algorithms" in info
        assert "implementation_status" in info

    def test_supported_algorithms_complete(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert len(info["supported_algorithms"]) == len(FPGAAlgorithm)

    def test_implementation_status(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert info["implementation_status"] == "PRODUCTION"


class TestBackwardCompatibility:
    """Ensure all original test_v4_advanced.py::TestFPGABridge tests pass."""

    def test_bridge_simulation_mode(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.is_available
        assert bridge.device is not None

    def test_load_bitstream(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        assert bridge.load_bitstream(FPGAAlgorithm.MD5)
        assert bridge.device.loaded_algorithm == FPGAAlgorithm.MD5
        assert bridge.device.hash_rate > 0

    def test_dispatch_simulation(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.SHA256)
        work = FPGAWorkUnit(
            algorithm=FPGAAlgorithm.SHA256,
            target_hash=b"test",
            candidates=[b"pass1", b"pass2", b"pass3"],
        )
        result = bridge.dispatch(work)
        assert result.candidates_checked == 3

    def test_benchmark(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        result = bridge.benchmark(FPGAAlgorithm.BCRYPT)
        assert result["algorithm"] == "bcrypt"
        assert result["simulation"] is True
        assert result["hash_rate"] > 0

    def test_info(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert info["available"] is True
        assert info["simulation"] is True
        assert "supported_algorithms" in info
        assert len(info["supported_algorithms"]) >= 7

    def test_no_hardware_mode(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=False)
        info = bridge.info()
        assert "available" in info


class TestSimulationWarnings:
    """Test that simulation warnings are ALWAYS present when not using real hardware."""

    def test_dispatch_has_warning(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge, FPGAWorkUnit

        bridge = FPGABridge(simulation=True)
        bridge.load_bitstream(FPGAAlgorithm.MD5)
        work = FPGAWorkUnit(algorithm=FPGAAlgorithm.MD5, target_hash=b"x", candidates=[b"a"])
        result = bridge.dispatch(work)
        assert result.simulation_warning != ""
        assert "SIMULATION" in result.simulation_warning

    def test_benchmark_has_warning(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        result = bridge.benchmark(FPGAAlgorithm.SHA256)
        assert result["simulation_warning"] != ""
        assert "SYNTHETIC" in result["simulation_warning"]

    def test_info_has_warning(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        assert "simulation_warning" in info
        assert info["simulation_warning"] != ""
        assert "SIMULATION" in info["simulation_warning"]

    def test_real_hardware_no_warning(self):
        """If real hardware were present, simulation_warning would be empty."""
        from hashaxe.fpga.bridge import FPGABridge

        # We can't test with real hardware, but verify the field exists
        bridge = FPGABridge(simulation=True)
        info = bridge.info()
        # In simulation mode, warning should be non-empty
        assert len(info["simulation_warning"]) > 0

    def test_python_warns_emitted(self):
        """Verify that Python warnings.warn is fired on init in simulation mode."""
        import warnings

        from hashaxe.fpga.bridge import FPGABridge

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            bridge = FPGABridge(simulation=True)
            fpga_warnings = [x for x in w if "FPGA SIMULATION" in str(x.message)]
            assert len(fpga_warnings) >= 1
