# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_v4_advanced.py
#  Tests for V1 Phases 5-10 covering Quantum, PQC, IPFS, SNN, FPGA, Web3/ZKP.
#  108 tests across 8 test classes for advanced features.
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
tests/test_v4_advanced.py — Tests for V1 Phases 5-10.

Covers: Quantum, PQC, IPFS, SNN, FPGA, Web3/ZKP
108 tests across 8 test classes.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: Quantum Computing Bridge
# ═══════════════════════════════════════════════════════════════════════════════


class TestQiskitBridge:

    def test_bridge_init(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge(prefer_gpu=False)
        info = bridge.info()
        assert "qiskit_available" in info

    def test_grover_speedup_small(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge()
        result = bridge.estimate_grover_speedup(keyspace=256)
        assert result["classical_ops"] == 256
        assert result["quantum_ops"] == 16  # √256
        assert result["speedup_factor"] == 16.0
        assert result["required_qubits"] == 9  # ceil(log2(256)) + 1

    def test_grover_speedup_large(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge()
        result = bridge.estimate_grover_speedup(keyspace=2**40)
        assert result["speedup_factor"] > 1_000_000
        assert "NEAR_TERM" in result["feasibility"] or "FAULT_TOLERANT" in result["feasibility"]

    def test_grover_speedup_zero(self):
        from hashaxe.quantum.qiskit_bridge import QiskitBridge

        bridge = QiskitBridge()
        result = bridge.estimate_grover_speedup(keyspace=0)
        assert "error" in result

    def test_backend_info(self):
        from hashaxe.quantum.qiskit_bridge import QuantumBackendInfo

        info = QuantumBackendInfo(name="test", max_qubits=20)
        assert info.name == "test"
        assert info.max_qubits == 20


class TestGroverOracle:

    def test_classical_simulation_4_qubits(self):
        from hashaxe.quantum.grover_oracle import GroverOracle

        oracle = GroverOracle()
        result = oracle.search(n_qubits=4, target=7, shots=10000)
        assert result.success
        assert result.found == 7
        assert result.probability > 0.5
        assert result.iterations > 0

    def test_classical_simulation_3_qubits(self):
        from hashaxe.quantum.grover_oracle import GroverOracle

        oracle = GroverOracle()
        result = oracle.search(n_qubits=3, target=5, shots=10000)
        assert result.success
        assert result.found == 5

    def test_classical_simulation_2_qubits(self):
        from hashaxe.quantum.grover_oracle import GroverOracle

        oracle = GroverOracle()
        result = oracle.search(n_qubits=2, target=3, shots=10000)
        assert result.success
        assert result.qubits == 2

    def test_benchmark(self):
        from hashaxe.quantum.grover_oracle import GroverOracle

        oracle = GroverOracle()
        results = oracle.benchmark(max_qubits=10)
        assert len(results) == 9  # 2 to 10
        assert results[0]["qubits"] == 2
        assert results[0]["keyspace"] == 4
        assert all(r["speedup"] > 1 for r in results)

    def test_invalid_target(self):
        from hashaxe.quantum.grover_oracle import GroverOracle

        oracle = GroverOracle()
        result = oracle.search(n_qubits=3, target=100)  # > 2^3
        assert not result.success


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 6: PQC Scanner
# ═══════════════════════════════════════════════════════════════════════════════


class TestPQCScanner:

    def test_scan_rsa_2048(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa-2048")
        assert result.risk == QuantumRisk.VULNERABLE
        assert "ML-KEM" in result.recommendation

    def test_scan_aes_256_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("aes-256")
        assert result.risk == QuantumRisk.SAFE

    def test_scan_ed25519(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("ed25519")
        assert result.risk == QuantumRisk.VULNERABLE
        assert result.qubits_needed > 0

    def test_scan_argon2_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("argon2")
        assert result.risk == QuantumRisk.SAFE

    def test_scan_ml_kem_safe(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("ml-kem")
        assert result.risk == QuantumRisk.SAFE

    def test_scan_unknown_algorithm(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("super_custom_algo")
        assert result.risk == QuantumRisk.UNKNOWN

    def test_scan_alias_rsa(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_algorithm("rsa")
        assert result.risk == QuantumRisk.VULNERABLE

    def test_scan_md5_hash(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_hash("5d41402abc4b2a76b9719d911017c592")
        assert result.risk == QuantumRisk.VULNERABLE
        assert result.asset_type == "hash"

    def test_scan_bcrypt_hash(self):
        from hashaxe.pqc.scanner import PQCScanner, QuantumRisk

        scanner = PQCScanner()
        result = scanner.scan_hash("$2b$12$LJ3m4ys3Lg.XTn6fY/Y1d.xxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert result.risk == QuantumRisk.PARTIAL

    def test_risk_score(self):
        from hashaxe.pqc.scanner import PQCScanner

        scanner = PQCScanner()
        r1 = scanner.scan_algorithm("rsa-1024")
        r2 = scanner.scan_algorithm("aes-256")
        assert r1.risk_score > r2.risk_score

    def test_full_report(self):
        from hashaxe.pqc.scanner import PQCScanner

        scanner = PQCScanner()
        results = [
            scanner.scan_algorithm("rsa-2048"),
            scanner.scan_algorithm("aes-256"),
            scanner.scan_algorithm("ed25519"),
        ]
        report = scanner.full_report(results)
        assert report["total_assets"] == 3
        assert report["quantum_vulnerable"] >= 2

    def test_scan_ssh_key_missing(self):
        from hashaxe.pqc.scanner import PQCScanner

        scanner = PQCScanner()
        result = scanner.scan_ssh_key("/nonexistent/key")
        assert "not found" in result.details.lower()


class TestHNDLAnalyzer:

    def test_critical_risk(self):
        from hashaxe.pqc.hndl_analyzer import HNDLAnalyzer, HNDLRisk

        analyzer = HNDLAnalyzer(q_day_estimate=2028, current_year=2026)
        result = analyzer.assess("rsa-2048", data_shelf_life_years=20, migration_timeline_years=5)
        assert result.risk == HNDLRisk.CRITICAL
        assert result.risk_score == 100

    def test_safe_risk(self):
        from hashaxe.pqc.hndl_analyzer import HNDLAnalyzer, HNDLRisk

        analyzer = HNDLAnalyzer(q_day_estimate=2040, current_year=2026)
        result = analyzer.assess("rsa-2048", data_shelf_life_years=5, migration_timeline_years=2)
        assert result.risk == HNDLRisk.SAFE

    def test_high_risk(self):
        from hashaxe.pqc.hndl_analyzer import HNDLAnalyzer, HNDLRisk

        analyzer = HNDLAnalyzer(q_day_estimate=2030, current_year=2026)
        result = analyzer.assess("rsa-2048", data_shelf_life_years=30, migration_timeline_years=2)
        assert result.risk in (HNDLRisk.HIGH, HNDLRisk.CRITICAL)

    def test_batch_assessment(self):
        from hashaxe.pqc.hndl_analyzer import HNDLAnalyzer

        analyzer = HNDLAnalyzer()
        results = analyzer.assess_batch(["rsa-2048", "aes-256", "ed25519"])
        assert len(results) == 3

    def test_generate_report(self):
        from hashaxe.pqc.hndl_analyzer import HNDLAnalyzer

        analyzer = HNDLAnalyzer(q_day_estimate=2028, current_year=2026)
        assessments = analyzer.assess_batch(
            ["rsa-2048", "ed25519"],
            data_shelf_life_years=20,
            migration_timeline_years=5,
        )
        report = analyzer.generate_report(assessments)
        assert report["total_assessed"] == 2
        assert "critical" in report


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 7: IPFS Swarm
# ═══════════════════════════════════════════════════════════════════════════════


class TestIPFSNode:

    def test_node_init(self):
        from hashaxe.distributed.ipfs_node import IPFSNode

        node = IPFSNode()
        info = node.info()
        assert "ipfs_available" in info
        assert "cache_dir" in info

    def test_publish_local_fallback(self):
        from hashaxe.distributed.ipfs_node import IPFSNode

        node = IPFSNode()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test wordlist\n" * 100)
            path = f.name
        try:
            asset = node.publish(path)
            assert asset.name.endswith(".txt")
            assert asset.size_bytes > 0
            assert asset.file_hash != ""
            assert asset.protocol in ("ipfs", "local")
        finally:
            os.unlink(path)

    def test_publish_missing_file(self):
        from hashaxe.distributed.ipfs_node import IPFSNode

        node = IPFSNode()
        with pytest.raises(FileNotFoundError):
            node.publish("/nonexistent/file.txt")

    def test_list_cached(self):
        from hashaxe.distributed.ipfs_node import IPFSNode

        node = IPFSNode()
        cached = node.list_cached()
        assert isinstance(cached, list)

    def test_swarm_asset_dataclass(self):
        from hashaxe.distributed.ipfs_node import SwarmAsset

        asset = SwarmAsset(name="test.txt", cid="Qm123", size_bytes=1000)
        assert asset.name == "test.txt"
        assert asset.cid == "Qm123"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 8: SNN / Neuromorphic
# ═══════════════════════════════════════════════════════════════════════════════


class TestSpikingEngine:

    def test_engine_init(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        info = engine.info()
        assert info["layout"] == "QWERTY"
        assert info["keys_mapped"] > 0

    def test_generate_row_patterns(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        patterns = list(engine.generate_row_patterns(min_len=4, max_len=6))
        assert len(patterns) > 0
        assert "qwer" in patterns or "qwert" in patterns

    def test_generate_diagonal_patterns(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        patterns = list(engine.generate_diagonal_patterns(min_len=3, max_len=4))
        assert len(patterns) > 0

    def test_generate_walks(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        walks = []
        for i, w in enumerate(engine.generate_walks(min_len=4, max_len=5, start_keys="q")):
            walks.append(w)
            if i > 50:
                break
        assert len(walks) > 0
        assert all(len(w) >= 4 for w in walks)

    def test_detect_pattern_qwerty(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        patterns = engine.detect_pattern("qwerty123")
        row_patterns = [p for p in patterns if p.pattern_type == "row"]
        assert len(row_patterns) > 0

    def test_generate_cluster_passwords(self):
        from hashaxe.ai.spiking_engine import SpikingEngine

        engine = SpikingEngine()
        clusters = list(engine.generate_cluster_passwords(cluster_count=2, min_len=4))
        assert len(clusters) > 0

    def test_adjacency_map(self):
        from hashaxe.ai.spiking_engine import QWERTY_ADJACENCY

        assert "q" in QWERTY_ADJACENCY
        assert "w" in QWERTY_ADJACENCY["q"]  # w is adjacent to q


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 9: FPGA Bridge
# ═══════════════════════════════════════════════════════════════════════════════


class TestFPGABridge:

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

    def test_all_algorithms(self):
        from hashaxe.fpga.bridge import FPGAAlgorithm, FPGABridge

        bridge = FPGABridge(simulation=True)
        for algo in FPGAAlgorithm:
            assert bridge.load_bitstream(algo)
            assert bridge.device.hash_rate > 0

    def test_no_hardware_mode(self):
        from hashaxe.fpga.bridge import FPGABridge

        bridge = FPGABridge(simulation=False)
        # May or may not find hardware, but shouldn't crash
        info = bridge.info()
        assert "available" in info


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 10: Web3 / ZKP
# ═══════════════════════════════════════════════════════════════════════════════


class TestZKAuditor:

    def test_auditor_init(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        assert auditor is not None

    def test_analyze_ethereum_wallet(self):
        from hashaxe.web3.zk_auditor import WalletType, ZKAuditor

        wallet_data = {
            "address": "0x1234567890abcdef",
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {"n": 262144, "r": 8, "p": 1},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wallet_data, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            analysis = auditor.analyze_wallet(path)
            assert analysis.wallet_type == WalletType.ETHEREUM_V3
            assert analysis.kdf == "scrypt"
            assert analysis.hashaxeable is True
        finally:
            os.unlink(path)

    def test_analyze_weak_pbkdf2(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, ZKAuditor

        wallet_data = {
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "pbkdf2",
                "kdfparams": {"c": 1000},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wallet_data, f)
            path = f.name
        try:
            auditor = ZKAuditor()
            analysis = auditor.analyze_wallet(path)
            critical = [f for f in analysis.findings if f.severity == AuditSeverity.CRITICAL]
            assert len(critical) > 0
        finally:
            os.unlink(path)

    def test_analyze_missing_wallet(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        analysis = auditor.analyze_wallet("/nonexistent/wallet.json")
        assert len(analysis.findings) > 0

    def test_audit_mnemonic_valid(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        findings = auditor.audit_mnemonic(
            "abandon ability able about above absent absorb abstract absurd abuse access accident"
        )
        # Should find it's 12-word = 128 bits info
        assert any(f.category == "entropy" for f in findings)

    def test_audit_mnemonic_wrong_length(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, ZKAuditor

        auditor = ZKAuditor()
        findings = auditor.audit_mnemonic("word1 word2 word3")
        critical = [f for f in findings if f.severity == AuditSeverity.CRITICAL]
        assert len(critical) > 0

    def test_audit_mnemonic_duplicates(self):
        from hashaxe.web3.zk_auditor import AuditSeverity, ZKAuditor

        auditor = ZKAuditor()
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        findings = auditor.audit_mnemonic(mnemonic)
        dups = [f for f in findings if "duplicate" in f.title.lower()]
        assert len(dups) > 0

    def test_estimate_mnemonic_hashaxe(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=11, total_words=12)
        assert result["unknown_words"] == 1
        assert result["keyspace"] == 2048
        assert result["feasibility"] in ("TRIVIAL", "EASY")

    def test_estimate_mnemonic_hashaxe_hard(self):
        from hashaxe.web3.zk_auditor import ZKAuditor

        auditor = ZKAuditor()
        result = auditor.estimate_mnemonic_hashaxe(known_words=0, total_words=12)
        assert result["unknown_words"] == 12
        assert result["feasibility"] == "INFEASIBLE"

    def test_full_report(self):
        from hashaxe.web3.zk_auditor import AuditFinding, AuditSeverity, WalletAnalysis, ZKAuditor

        auditor = ZKAuditor()
        wallet = WalletAnalysis(
            hashaxeable=True,
            findings=[
                AuditFinding(severity=AuditSeverity.HIGH, title="Weak KDF"),
            ],
        )
        report = auditor.full_report([wallet])
        assert report["total_wallets"] == 1
        assert report["high_findings"] == 1
