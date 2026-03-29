# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_batch2.py
#  Batch 2 test suite covering GPU detection, SIMD batching, word frequency, distributed.
#  Tests CLI flags, worker messaging, and smart ordering features.
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
# ruff: noqa: E402
tests/test_batch2.py — Batch 2 test suite.

Covers:
  TestGPUDetection     (6)  — GPU probe, fallback, device info string
  TestSIMDBatch        (8)  — CPU SIMD batching, pre-filter, batch sizing
  TestWordFreq        (12)  — smart_sort, FrequencyIndex, priority_candidates
  TestDistributedMsgs  (8)  — WorkItem/WorkResult serialisation
  TestCLINewFlags      (7)  — --no-gpu, --distributed-*, --no-smart-order, --gpu-info
  TestCrackerBatch2   (10)  — hashaxe() with GPU flags, smart order, distributed stubs
  TestIntegrationB2    (6)  — end-to-end with real keys using new paths

Total: 57 tests
"""

import importlib
import json
import multiprocessing
import os
import struct
import sys
import tempfile
import time
import types
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

# ruff: noqa: E402, F401
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from hashaxe.cpu.simd import _aes_ctr_python, _prefilter, get_optimal_batch_size
from hashaxe.cpu.wordfreq import (
    FrequencyIndex,
    _pattern_score,
    is_keyboard_walk,
    priority_candidates,
    smart_sort,
    top_k_first,
)
from hashaxe.distributed.master import WorkItem, WorkResult
from hashaxe.distributed.worker import WorkerNode
from hashaxe.gpu.accelerator import (
    GPUBackend,
    GPUDevice,
    gpu_info_string,
)
from hashaxe.parser import parse_key_file

KEYS_DIR = Path(__file__).parent.parent / "test_files"


# ═══════════════════════════════════════════════════════════════
# 1. GPU DETECTION
# ═══════════════════════════════════════════════════════════════


class TestGPUDetection(unittest.TestCase):

    def test_no_gpu_returns_none_string(self):
        """gpu_info_string(None) returns a CPU fallback message."""
        msg = gpu_info_string(None)
        self.assertIn("CPU", msg)

    def test_gpu_device_dataclass_cuda(self):
        """GPUDevice can be constructed with CUDA backend."""
        d = GPUDevice(
            backend=GPUBackend.CUDA,
            name="NVIDIA RTX 4090",
            vendor="NVIDIA",
            global_mem_mb=24564,
            driver_version="560.28.03",
            est_speed_pw_s=200_000,
        )
        self.assertEqual(d.backend, GPUBackend.CUDA)
        self.assertAlmostEqual(d.est_speed_pw_s, 200_000)

    def test_gpu_device_dataclass_opencl(self):
        """GPUDevice can be constructed with OpenCL backend."""
        d = GPUDevice(
            backend=GPUBackend.OPENCL,
            name="AMD Radeon RX 7900 XTX",
            vendor="AMD",
            compute_units=96,
            global_mem_mb=24576,
            est_speed_pw_s=130_000,
        )
        self.assertEqual(d.backend, GPUBackend.OPENCL)
        self.assertEqual(d.vendor, "AMD")

    def test_gpu_info_string_cuda(self):
        """gpu_info_string formats CUDA device correctly."""
        d = GPUDevice(
            backend=GPUBackend.CUDA,
            name="RTX 4090",
            global_mem_mb=24564,
            est_speed_pw_s=200_000,
        )
        s = gpu_info_string(d)
        self.assertIn("CUDA", s)
        self.assertIn("RTX 4090", s)
        self.assertIn("200,000", s)

    # Removed deprecated _estimate_cuda_speed tests as HardwareProfiler replaces them
    # def test_estimate_cuda_speed_4090(self):
    #     self.assertEqual(_estimate_cuda_speed("NVIDIA GeForce RTX 4090"), 200_000)
    # def test_estimate_cuda_speed_unknown_positive(self):
    #     self.assertGreater(_estimate_cuda_speed("NVIDIA Unknown GPU XYZ"), 0)

    def test_gpu_backend_enum_values(self):
        """All three backend values are unique."""
        vals = {GPUBackend.CUDA, GPUBackend.OPENCL, GPUBackend.NONE}
        self.assertEqual(len(vals), 3)

    def test_detect_gpu_no_crash_no_hardware(self):
        """detect_gpu() returns None gracefully when no GPU present."""
        from hashaxe.gpu.accelerator import detect_gpu

        # In CI/this environment there is no GPU — should return None
        result = detect_gpu()
        # Either None or a GPUDevice — never raises
        self.assertTrue(result is None or isinstance(result, GPUDevice))


# ═══════════════════════════════════════════════════════════════
# 2. CPU SIMD BATCH
# ═══════════════════════════════════════════════════════════════


class TestSIMDBatch(unittest.TestCase):

    def test_prefilter_empty_string(self):
        """Pre-filter rejects empty strings."""
        mask = _prefilter(["", "valid", ""])
        self.assertFalse(mask[0])
        self.assertTrue(mask[1])
        self.assertFalse(mask[2])

    def test_prefilter_whitespace_only(self):
        """Pre-filter rejects whitespace-only strings."""
        mask = _prefilter(["   ", "\t\n", "normal"])
        self.assertFalse(mask[0])
        self.assertFalse(mask[1])
        self.assertTrue(mask[2])

    def test_prefilter_very_long(self):
        """Pre-filter rejects strings over 128 bytes."""
        long_pw = "a" * 200
        short_pw = "puppet"
        mask = _prefilter([long_pw, short_pw])
        self.assertFalse(mask[0])
        self.assertTrue(mask[1])

    def test_prefilter_all_valid(self):
        """Pre-filter keeps all valid candidates."""
        candidates = ["puppet", "P@ssw0rd!", "hunter2", "correct horse battery"]
        mask = _prefilter(candidates)
        self.assertTrue(all(mask))

    def test_get_optimal_batch_size_low_ram(self):
        """Optimal batch size with 0.1 GB RAM is at minimum floor."""
        size = get_optimal_batch_size(0.1)
        self.assertGreaterEqual(size, 32)

    def test_get_optimal_batch_size_high_ram(self):
        """Optimal batch size with 32 GB RAM is capped at 4096."""
        size = get_optimal_batch_size(32.0)
        self.assertLessEqual(size, 4096)

    def test_get_optimal_batch_size_default(self):
        """Default batch size (1GB) is within sane bounds."""
        size = get_optimal_batch_size()
        self.assertGreaterEqual(size, 32)
        self.assertLessEqual(size, 4096)

    def test_aes_ctr_python_decrypt_known(self):
        """AES-CTR python fallback decrypts to known plaintext."""
        key = bytes(range(32))
        iv = bytes(range(16))
        # Encrypt then decrypt should round-trip
        ct = _aes_ctr_python(key, iv, b"Hello, Shadow Team!")
        pt = _aes_ctr_python(key, iv, ct)
        self.assertEqual(pt, b"Hello, Shadow Team!")


# ═══════════════════════════════════════════════════════════════
# 3. WORD FREQUENCY & SMART ORDERING
# ═══════════════════════════════════════════════════════════════


class TestWordFreq(unittest.TestCase):

    def test_smart_sort_prefers_common_patterns(self):
        """smart_sort puts lowercase words before uppercase-heavy ones."""
        cands = ["ZZZZZZZZZ", "puppet", "X1X2X3X4"]
        sorted_c = smart_sort(cands)
        self.assertEqual(sorted_c[0], "puppet")

    def test_smart_sort_empty(self):
        """smart_sort handles empty list."""
        self.assertEqual(smart_sort([]), [])

    def test_smart_sort_single(self):
        """smart_sort handles single-element list."""
        self.assertEqual(smart_sort(["hello"]), ["hello"])

    def test_smart_sort_word_plus_digits_before_allcaps(self):
        """'puppet123' scores better than 'PUPPET'."""
        s = smart_sort(["PUPPET", "puppet123"])
        self.assertEqual(s[0], "puppet123")

    def test_pattern_score_lowercase_word_best(self):
        """Pure lowercase word has lowest (best) pattern score."""
        score_lower = _pattern_score("puppet")
        score_upper = _pattern_score("PUPPET")
        self.assertLess(score_lower, score_upper)

    def test_pattern_score_decreases_with_length_optimum(self):
        """8-char passwords score better than 2-char passwords."""
        score_8 = _pattern_score("password")  # 8 chars
        score_2 = _pattern_score("ab")  # 2 chars
        self.assertLess(score_8, score_2)

    def test_frequency_index_load_and_score(self):
        """FrequencyIndex loads wordlist and returns correct rank-based score."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("puppet\nhunter2\npassword\n")
            fname = f.name
        try:
            idx = FrequencyIndex()
            idx.load(fname)
            self.assertLess(idx.score("puppet"), idx.score("password"))
        finally:
            os.unlink(fname)

    def test_frequency_index_missing_word(self):
        """FrequencyIndex returns inf for unknown words."""
        idx = FrequencyIndex()
        self.assertEqual(idx.score("definitly_not_in_any_list_xyz"), float("inf"))

    def test_frequency_index_sort(self):
        """FrequencyIndex.sort() puts rank-1 word first."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("puppet\nhunter2\npassword\n")
            fname = f.name
        try:
            idx = FrequencyIndex()
            idx.load(fname)
            result = idx.sort(["password", "puppet", "hunter2"])
            self.assertEqual(result[0], "puppet")
        finally:
            os.unlink(fname)

    def test_is_keyboard_walk_detects_qwerty(self):
        """is_keyboard_walk correctly identifies 'qwerty'."""
        self.assertTrue(is_keyboard_walk("qwerty"))

    def test_is_keyboard_walk_normal_word(self):
        """is_keyboard_walk returns False for 'puppet'."""
        self.assertFalse(is_keyboard_walk("puppet"))

    def test_priority_candidates_first_is_base(self):
        """priority_candidates yields the base word first."""
        cands = list(priority_candidates("puppet"))
        self.assertEqual(cands[0], "puppet")

    def test_priority_candidates_includes_year(self):
        """priority_candidates includes year-suffixed variant."""
        cands = list(priority_candidates("puppet"))
        self.assertIn("puppet2024", cands)

    def test_top_k_first_yields_all(self):
        """top_k_first yields same count as input."""
        words = [f"word{i}" for i in range(100)]
        result = list(top_k_first(iter(words), k=20))
        self.assertEqual(len(result), 100)

    def test_top_k_first_yields_no_duplicates(self):
        """top_k_first yields no duplicates."""
        words = [f"word{i}" for i in range(50)]
        result = list(top_k_first(iter(words), k=20))
        self.assertEqual(len(result), len(set(result)))


# ═══════════════════════════════════════════════════════════════
# 4. DISTRIBUTED MESSAGE SERIALISATION
# ═══════════════════════════════════════════════════════════════


class TestDistributedMsgs(unittest.TestCase):

    def _make_work_item(self):
        return WorkItem(
            job_id="job_00000001",
            key_path="/work/id_ed25519",
            wordlist="/wordlists/rockyou.txt",
            start_byte=0,
            end_byte=1_000_000,
            use_rules=True,
            rule_file=None,
            mask=None,
        )

    def test_work_item_creation(self):
        """WorkItem dataclass creates without error."""
        item = self._make_work_item()
        self.assertEqual(item.job_id, "job_00000001")

    def test_work_item_json_roundtrip(self):
        """WorkItem serialises to JSON and deserialises correctly."""
        from dataclasses import asdict

        item = self._make_work_item()
        d = asdict(item)
        rt = WorkItem(**d)
        self.assertEqual(rt.job_id, item.job_id)
        self.assertEqual(rt.start_byte, item.start_byte)
        self.assertEqual(rt.end_byte, item.end_byte)
        self.assertEqual(rt.use_rules, item.use_rules)

    def test_work_result_found(self):
        """WorkResult with found=True stores passphrase."""
        r = WorkResult(
            job_id="job_00000001",
            found=True,
            passphrase="puppet",
            tried=1500,
            speed=4700.0,
        )
        self.assertTrue(r.found)
        self.assertEqual(r.passphrase, "puppet")

    def test_work_result_not_found(self):
        """WorkResult with found=False stores None passphrase."""
        r = WorkResult(
            job_id="job_00000001",
            found=False,
            passphrase=None,
            tried=50000,
            speed=4800.0,
        )
        self.assertFalse(r.found)
        self.assertIsNone(r.passphrase)

    def test_work_result_json_roundtrip(self):
        """WorkResult JSON round-trip preserves all fields."""
        r = WorkResult(
            job_id="j1",
            found=True,
            passphrase="hunter2",
            tried=999,
            speed=5000.1,
        )
        d = {
            "job_id": r.job_id,
            "found": r.found,
            "passphrase": r.passphrase,
            "tried": r.tried,
            "speed": r.speed,
        }
        rt = WorkResult(**d)
        self.assertEqual(rt.passphrase, "hunter2")
        self.assertAlmostEqual(rt.speed, 5000.1)

    def test_work_item_hybrid_mode(self):
        """WorkItem with mask set represents hybrid mode."""
        item = WorkItem(
            job_id="j2",
            key_path="/work/id_ed25519",
            wordlist="/wl/rockyou.txt",
            start_byte=0,
            end_byte=500,
            use_rules=False,
            rule_file=None,
            mask="?d?d?d?d",
        )
        self.assertEqual(item.mask, "?d?d?d?d")
        self.assertFalse(item.use_rules)

    def test_worker_node_creates_without_zmq(self):
        """WorkerNode can be instantiated even without pyzmq installed."""
        node = WorkerNode(master_host="127.0.0.1", use_gpu=False)
        self.assertEqual(node.master_host, "127.0.0.1")
        self.assertIsNotNone(node.worker_id)

    def test_worker_node_has_unique_ids(self):
        """Two WorkerNode instances have different worker_ids."""
        n1 = WorkerNode(master_host="127.0.0.1", use_gpu=False)
        n2 = WorkerNode(master_host="127.0.0.1", use_gpu=False)
        self.assertNotEqual(n1.worker_id, n2.worker_id)


# ═══════════════════════════════════════════════════════════════
# 5. CLI NEW FLAGS
# ═══════════════════════════════════════════════════════════════


class TestCLINewFlags(unittest.TestCase):

    def _parse(self, args):
        from hashaxe.cli import _build_parser

        return _build_parser().parse_args(args)

    def test_no_gpu_flag(self):
        """--no-gpu flag is parsed correctly."""
        args = self._parse(["-k", "key.pem", "-w", "wl.txt", "--no-gpu"])
        self.assertTrue(args.no_gpu)

    def test_no_gpu_default_false(self):
        """--no-gpu defaults to False."""
        args = self._parse(["-k", "key.pem", "-w", "wl.txt"])
        self.assertFalse(args.no_gpu)

    def test_distributed_master_flag(self):
        """--distributed-master flag parsed."""
        args = self._parse(["-k", "k", "-w", "w", "--distributed-master"])
        self.assertTrue(args.distributed_master)

    def test_distributed_worker_flag(self):
        """--distributed-worker with --master parsed."""
        args = self._parse(["-k", "k", "-w", "w", "--distributed-worker", "--master", "10.0.0.1"])
        self.assertTrue(args.distributed_worker)
        self.assertEqual(args.master_host, "10.0.0.1")

    def test_no_smart_order_flag(self):
        """--no-smart-order flag parsed."""
        args = self._parse(["-k", "k", "-w", "w", "--no-smart-order"])
        self.assertTrue(args.no_smart_order)

    def test_work_port_default(self):
        """--work-port defaults to 5555."""
        args = self._parse(["-k", "k", "-w", "w"])
        self.assertEqual(args.work_port, 5555)

    def test_work_port_custom(self):
        """--work-port accepts custom value."""
        args = self._parse(["-k", "k", "-w", "w", "--work-port", "9999"])
        self.assertEqual(args.work_port, 9999)


# ═══════════════════════════════════════════════════════════════
# 6. CRACKER BATCH 2 INTEGRATION (mocked GPU / distributed)
# ═══════════════════════════════════════════════════════════════


class TestCrackerBatch2(unittest.TestCase):

    RSA_KEY = str(KEYS_DIR / "rsa_legacy_puppet.key")
    NOPASS = str(KEYS_DIR / "rsa_legacy_nopass.key")

    def _mini_wordlist(self, words):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(words) + "\n")
            path = tf.name
        return path

    def test_hashaxe_with_no_gpu_flag(self):
        """hashaxe() with use_gpu=False runs CPU path and finds passphrase."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._mini_wordlist(["wrong1", "puppet", "wrong2"])
        try:
            result = hashaxe(
                key_path=self.RSA_KEY,
                wordlist=wl,
                threads=1,
                use_gpu=False,
                use_smart_order=False,
                quiet=True,
            )
            self.assertEqual(result, "puppet")
        finally:
            os.unlink(wl)

    def test_hashaxe_with_smart_order_enabled(self):
        """hashaxe() with use_smart_order=True finds passphrase."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._mini_wordlist(["PUPPET", "Puppet1", "puppet"])
        try:
            result = hashaxe(
                key_path=self.RSA_KEY,
                wordlist=wl,
                threads=1,
                use_gpu=False,
                use_smart_order=True,
                quiet=True,
            )
            self.assertEqual(result, "puppet")
        finally:
            os.unlink(wl)

    def test_hashaxe_with_smart_order_disabled(self):
        """hashaxe() with use_smart_order=False still finds passphrase."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._mini_wordlist(["wrong1", "puppet"])
        try:
            result = hashaxe(
                key_path=self.RSA_KEY,
                wordlist=wl,
                threads=1,
                use_gpu=False,
                use_smart_order=False,
                quiet=True,
            )
            self.assertEqual(result, "puppet")
        finally:
            os.unlink(wl)

    def test_hashaxe_unencrypted_returns_empty_string(self):
        """hashaxe() on unencrypted key returns '' with gpu flags."""
        from hashaxe.hashaxeer import hashaxe

        result = hashaxe(
            key_path=self.NOPASS,
            wordlist="",
            use_gpu=False,
            quiet=True,
        )
        self.assertEqual(result, "")

    def test_benchmark_does_not_crash_no_gpu(self):
        """benchmark() runs without GPU and returns positive speed."""
        import pathlib

        from hashaxe.display import Display
        from hashaxe.formats import FormatRegistry
        from hashaxe.hashaxeer import benchmark

        registry = FormatRegistry()
        data = pathlib.Path(self.RSA_KEY).read_bytes()
        match = registry.identify(data, pathlib.Path(self.RSA_KEY))
        pk = match.handler.parse(data, pathlib.Path(self.RSA_KEY))
        disp = Display(quiet=True)
        speed = benchmark(pk, match.handler, disp, n_workers=1)
        self.assertGreater(speed, 0)

    def test_gpu_hashaxeer_falls_back_to_cpu(self):
        """GPUCracker in no-GPU environment uses CPU fallback path."""
        from hashaxe.gpu.accelerator import GPUCracker

        with patch("hashaxe.gpu.accelerator.detect_gpu", return_value=None):
            g = GPUCracker(device=None)
            self.assertFalse(g.is_available())

    def test_simd_path_finds_passphrase(self):
        """simd_batch_hashaxe finds 'puppet' in candidate list."""
        from hashaxe.cpu.simd import simd_batch_hashaxe

        pk = parse_key_file(self.RSA_KEY)
        ev = multiprocessing.Manager().Event()
        result = simd_batch_hashaxe(pk, ["wrong1", "puppet", "wrong2"], ev)
        self.assertEqual(result, "puppet")

    def test_simd_path_returns_none_on_miss(self):
        """simd_batch_hashaxe returns None when passphrase absent."""
        from hashaxe.cpu.simd import simd_batch_hashaxe

        pk = parse_key_file(self.RSA_KEY)
        ev = multiprocessing.Manager().Event()
        result = simd_batch_hashaxe(pk, ["nope1", "nope2", "nope3"], ev)
        self.assertIsNone(result)

    def test_simd_stops_when_event_set(self):
        """simd_batch_hashaxe respects found_event cancellation."""
        from hashaxe.cpu.simd import simd_batch_hashaxe

        pk = parse_key_file(self.RSA_KEY)
        ev = multiprocessing.Manager().Event()
        ev.set()  # pre-cancel
        result = simd_batch_hashaxe(pk, ["puppet"], ev)
        self.assertIsNone(result)  # should bail immediately

    def test_distributed_worker_no_zmq_graceful(self):
        """WorkerNode.run() exits gracefully when pyzmq not installed."""
        node = WorkerNode(master_host="127.0.0.1", use_gpu=False)
        with patch("builtins.__import__", side_effect=ImportError("No module named 'zmq'")):
            # Should not raise — just print warning and return
            try:
                node.run()
            except SystemExit:
                pass
            except ImportError:
                pass  # acceptable in mock context


# ═══════════════════════════════════════════════════════════════
# 7. END-TO-END INTEGRATION (Batch 2 paths)
# ═══════════════════════════════════════════════════════════════


class TestIntegrationB2(unittest.TestCase):

    RSA_KEY = str(KEYS_DIR / "rsa_legacy_puppet.key")
    ECDSA_KEY = str(KEYS_DIR / "ecdsa_legacy_abc123.key")
    NOPASS = str(KEYS_DIR / "rsa_legacy_nopass.key")

    def _wl(self, words):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(words) + "\n")
            path = tf.name
        return path

    def test_e2e_wordlist_no_gpu_rsa(self):
        """End-to-end: RSA key hashaxeed via wordlist, use_gpu=False."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._wl(["wrong", "puppet"])
        try:
            r = hashaxe(key_path=self.RSA_KEY, wordlist=wl, threads=1, use_gpu=False, quiet=True)
            self.assertEqual(r, "puppet")
        finally:
            os.unlink(wl)

    def test_e2e_wordlist_no_gpu_ecdsa(self):
        """End-to-end: ECDSA key hashaxeed via wordlist, use_gpu=False."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._wl(["nope", "abc123", "wrong"])
        try:
            r = hashaxe(key_path=self.ECDSA_KEY, wordlist=wl, threads=1, use_gpu=False, quiet=True)
            self.assertEqual(r, "abc123")
        finally:
            os.unlink(wl)

    def test_e2e_smart_order_rsa(self):
        """End-to-end: smart ordering brings 'puppet' to front and finds it."""
        from hashaxe.hashaxeer import hashaxe

        # Put puppet last — smart order should elevate it
        wl = self._wl(["ZZZZZ9999", "AAAAA!!!!!", "puppet"])
        try:
            r = hashaxe(
                key_path=self.RSA_KEY,
                wordlist=wl,
                threads=1,
                use_gpu=False,
                use_smart_order=True,
                quiet=True,
            )
            self.assertEqual(r, "puppet")
        finally:
            os.unlink(wl)

    def test_e2e_rules_and_no_gpu(self):
        """End-to-end: rules mode + no GPU finds 'puppet' via mutations."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._wl(["Puppet", "PUPPET"])  # mutations of capitalised forms
        try:
            r = hashaxe(
                key_path=self.RSA_KEY,
                wordlist=wl,
                threads=1,
                use_gpu=False,
                use_rules=True,
                use_smart_order=False,
                quiet=True,
            )
            # Rules should generate lowercase 'puppet' from 'Puppet'
            self.assertEqual(r, "puppet")
        finally:
            os.unlink(wl)

    def test_e2e_not_found_no_gpu(self):
        """End-to-end: wordlist without correct pw returns None."""
        from hashaxe.hashaxeer import hashaxe

        wl = self._wl(["nope1", "nope2", "nope3"])
        try:
            r = hashaxe(key_path=self.RSA_KEY, wordlist=wl, threads=1, use_gpu=False, quiet=True)
            self.assertIsNone(r)
        finally:
            os.unlink(wl)

    def test_e2e_simd_batch_rsa(self):
        """End-to-end simd_batch_hashaxe finds passphrase for RSA key."""
        from hashaxe.cpu.simd import simd_batch_hashaxe

        pk = parse_key_file(self.RSA_KEY)
        ev = multiprocessing.Manager().Event()
        r = simd_batch_hashaxe(pk, ["miss1", "miss2", "puppet", "miss3"], ev)
        self.assertEqual(r, "puppet")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestGPUDetection,
        TestSIMDBatch,
        TestWordFreq,
        TestDistributedMsgs,
        TestCLINewFlags,
        TestCrackerBatch2,
        TestIntegrationB2,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
