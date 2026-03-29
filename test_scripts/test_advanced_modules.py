import sys
import os

# Add the current directory to sys.path so we can import hashaxe
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from hashaxe.web3.zk_auditor import ZKAuditor
from hashaxe.pqc.scanner import PQCScanner
from hashaxe.quantum.qiskit_bridge import QiskitBridge
from hashaxe.fpga.bridge import FPGABridge, FPGAAlgorithm
import json

print("\n" + "="*50)
print(" 🌐 TESTING WEB3 ZK-AUDITOR ")
print("="*50)
auditor = ZKAuditor()
mnemonic = "abandon abandon ability about above absent absorb abstract absurd abuse access account"
print(f"Auditing Mnemonic: {mnemonic}")
findings = auditor.audit_mnemonic(mnemonic)
print(json.dumps([f.__dict__ for f in findings], indent=2, default=str))

estimate = auditor.estimate_mnemonic_hashaxe(known_words=10, total_words=12)
print("\nEstimate mnemonic hashaxe (10/12 known):")
print(json.dumps(estimate, indent=2))

print("\n" + "="*50)
print(" ⚛️ TESTING POST-QUANTUM (PQC) SCANNER ")
print("="*50)
pqc = PQCScanner()
ssh_algo = "rsa-2048"
print(f"Scanning algorithm: {ssh_algo}")
pqc_result = pqc.scan_algorithm(ssh_algo)
print(json.dumps(pqc_result.__dict__, indent=2, default=str))

hash_target = "$6$salt$hashstring123"
print(f"\nScanning hash format: {hash_target}")
hash_result = pqc.scan_hash(hash_target)
print(json.dumps(hash_result.__dict__, indent=2, default=str))


print("\n" + "="*50)
print(" 🌌 TESTING QUANTUM BRIDGE (SIMULATED) ")
print("="*50)
q_bridge = QiskitBridge()
print("Quantum Backend Info:")
print(json.dumps(q_bridge.info(), indent=2))

keyspace = 100000000
print(f"\nEstimating Grover's algorithm speedup for keyspace = {keyspace}:")
print(json.dumps(q_bridge.estimate_grover_speedup(keyspace), indent=2))


print("\n" + "="*50)
print(" 📟 TESTING FPGA BRIDGE (ACCELERATOR) ")
print("="*50)
f_bridge = FPGABridge(simulation=True)
print("FPGA Info:")
print(json.dumps(f_bridge.info(), indent=2))

print("\nBenchmarking FPGA BCRYPT (Simulated):")
print(json.dumps(f_bridge.benchmark(FPGAAlgorithm.BCRYPT), indent=2))

