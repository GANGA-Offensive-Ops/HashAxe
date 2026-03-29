import hashlib
import os
import subprocess
import time

# Use relative path from test file location for portability
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)
WORK_DIR = os.path.join(PROJECT_ROOT, "manual_test_run")
reports = []

_FIXTURE_PW = "xr7kQ2m123"  # meaningless test value, NOT a real password
target_hash = hashlib.md5(_FIXTURE_PW.encode()).hexdigest()  # computed at runtime

osint_text_file = f"{WORK_DIR}/osint_profile.txt"
with open(osint_text_file, "w") as f:
    f.write("The target's name is Shadow. They were born in 123. They like passwords.\n")

commands = [
    {
        "id": "CMD-015",
        "cmd": ["python3", "-m", "hashaxe", "--hash", target_hash, "--osint-file", osint_text_file],
        "desc": "OSINT Profiling Attack",
    },
    {
        "id": "CMD-016",
        "cmd": ["python3", "-m", "hashaxe", "--hash", target_hash, "--ai", "--candidates", "50"],
        "desc": "AI Generator Attack (Markov fallback or GPT2)",
    },
    {
        "id": "CMD-017",
        "cmd": ["python3", "-m", "hashaxe", "--hash", target_hash, "--attack", "pcfg"],
        "desc": "PCFG Attack",
    },
    {
        "id": "CMD-018",
        # Test distributed master with a small keyspace (mask) to see it bind
        "cmd": [
            "python3",
            "-m",
            "hashaxe",
            "--hash",
            target_hash,
            "--distributed-master",
            "--mask",
            "?d?d",
        ],
        "desc": "Start distributed master node",
    },
]

for c in commands:
    print(f"Testing {c['id']}...")
    start = time.time()
    try:
        proc = subprocess.run(c["cmd"], capture_output=True, text=True, timeout=20)
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
                "Related Module": "attacks, osint, distributed, ai, pcfg",
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

with open(f"{WORK_DIR}/reports/batch4_report.md", "w") as f:
    f.write("# Testing Report: Batch 4\n\n")
    for r in reports:
        f.write(f"### {r['Command']}\n")
        f.write(f"**Status:** {r['Status']}\n")
        f.write(f"**Execution Time:** {r['Execution Time']}\n")
        f.write(f"**Root Cause / Error:** {r['Root Cause']}\n")
        f.write("```text\n")
        f.write(r["Result"][:500] + "\n...\n")
        f.write("```\n\n")

print("Batch 4 testing completed. Results saved.")
