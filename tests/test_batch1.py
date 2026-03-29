import hashlib
import json
import os
import subprocess
import time

# Use relative path from test file location for portability
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)
WORK_DIR = os.path.join(PROJECT_ROOT, "manual_test_run")
os.makedirs(f"{WORK_DIR}/logs", exist_ok=True)
os.makedirs(f"{WORK_DIR}/reports", exist_ok=True)
reports = []

# Mock inputs — use non-credential fixture strings
_FIXTURE_PW = "xr7kQ2m123"  # meaningless test value, NOT a real password
small_wordlist = f"{WORK_DIR}/test_words.txt"
with open(small_wordlist, "w") as f:
    f.write(f"test\nadmin\n{_FIXTURE_PW}\nfoobar\n")

md5_hash = hashlib.md5(_FIXTURE_PW.encode()).hexdigest()  # computed at runtime
with open(f"{WORK_DIR}/md5_hash.txt", "w") as f:
    f.write(md5_hash + "\n")

commands = [
    {
        "id": "CMD-001",
        "cmd": ["python3", "-m", "hashaxe", "--hash", md5_hash, "-w", small_wordlist],
        "desc": "Wordlist attack using inline hash",
    },
    {
        "id": "CMD-002",
        "cmd": ["python3", "-m", "hashaxe", "-k", f"{WORK_DIR}/md5_hash.txt", "-w", small_wordlist],
        "desc": "Wordlist attack using hash file",
    },
    {
        "id": "CMD-003",
        "cmd": ["python3", "-m", "hashaxe", "--hash", md5_hash, "--mask", "xr7kQ?d?d?d"],
        "desc": "Mask attack only",
    },
    {
        "id": "CMD-004",
        "cmd": [
            "python3",
            "-m",
            "hashaxe",
            "-k",
            f"{WORK_DIR}/md5_hash.txt",
            "-w",
            small_wordlist,
            "--mask",
            "?d?d?d",
        ],
        "desc": "Hybrid attack (wordlist + mask suffix)",
    },
    {
        "id": "CMD-005",
        "cmd": ["python3", "-m", "hashaxe", "--list-sessions"],
        "desc": "List sessions utility",
    },
]

for c in commands:
    print(f"Testing {c['id']}...")
    start = time.time()
    try:
        proc = subprocess.run(c["cmd"], capture_output=True, text=True, timeout=30)
        end = time.time()

        status = "FAIL"
        if proc.returncode == 0:
            status = "PASS"
            if "FAIL" in proc.stdout or "Error" in proc.stderr:
                status = "PARTIAL"
        elif proc.returncode == 124:  # Timeout
            status = "TIMEOUT"

        reports.append(
            {
                "Command": " ".join(c["cmd"]),
                "Result": proc.stdout[:1000] + "\nSTDERR:\n" + proc.stderr[:1000],
                "Execution Time": f"{end - start:.2f}s",
                "Status": status,
                "Root Cause": (
                    "Timeout"
                    if status == "TIMEOUT"
                    else ("Non-zero exit" if status == "FAIL" else "")
                ),
                "Related Module": "cli.py, hashaxeer.py",
            }
        )
    except Exception as e:
        reports.append(
            {
                "Command": " ".join(c["cmd"]),
                "Result": str(e),
                "Execution Time": "0s",
                "Status": "FAIL",
                "Root Cause": "Exception during execution",
                "Related Module": "Unknown",
            }
        )

with open(f"{WORK_DIR}/reports/batch1_report.md", "w") as f:
    f.write("# Testing Report: Batch 1\n\n")
    for r in reports:
        f.write(f"### {r['Command']}\n")
        f.write(f"**Status:** {r['Status']}\n")
        f.write(f"**Execution Time:** {r['Execution Time']}\n")
        f.write(f"**Root Cause / Error:** {r['Root Cause']}\n")
        f.write("```text\n")
        f.write(r["Result"][:500] + "\n...\n")
        f.write("```\n\n")

print("Batch 1 testing completed. Results saved.")
