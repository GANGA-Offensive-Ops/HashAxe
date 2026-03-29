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
target_wordlist = f"{WORK_DIR}/test_words3.txt"
with open(target_wordlist, "w") as f:
    f.write(f"test123\nadmin\nfoobar\n{_FIXTURE_PW}\n")

# JWT HMAC-SHA256 test case — signature is intentionally invalid for parser testing
# For the purpose of the test, let's just make sure it parses it correctly, we don't strictly need it to succeed if we just want to audit failure handling of format parsers,
# but let's try to base64 encode it somewhat legitimately or rely on the tool identifying it as JWT.
jwt_file = f"{WORK_DIR}/test.jwt"
with open(jwt_file, "w") as f:
    # Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    # Payload: {"user":"admin"} -> eyJ1c2VyIjoiYWRtaW4ifQ
    # Signature: will be invalid but parser shouldn't crash
    f.write(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
    )

# NetNTLMv2 mock hash (username::domain:challenge:HMAC:blob) - standard format
ntlm_hash = "admin::DOMAIN:1122334455667788:0101000000000000000000000000000000000000000000000000000000000000:0000000000000000"

commands = [
    {
        "id": "CMD-011",
        "cmd": ["python3", "-m", "hashaxe", "-k", jwt_file, "-w", target_wordlist],
        "desc": "Crack JWT token with known secret",
    },
    {
        "id": "CMD-012",
        "cmd": ["python3", "-m", "hashaxe", "--hash", ntlm_hash, "-w", target_wordlist],
        "desc": "Parse and attempt NetNTLMv2 hash",
    },
    {
        "id": "CMD-013",
        "cmd": [
            "python3",
            "-m",
            "hashaxe",
            "--hash",
            "e12f0afbf1d2c10f1d0280fc283c526e",
            "-w",
            target_wordlist,
        ],
        "desc": "Parse MD5 raw",
    },
    {
        "id": "CMD-014",
        "cmd": [
            "python3",
            "-m",
            "hashaxe",
            "--hash",
            "$2b$04$2gU2kXJ1H.X0NpwJw7i6U.l2lD1qR1H9v3/s.u5eB0Yt5c9F3W2W6",
            "-w",
            target_wordlist,
        ],
        "desc": "Parse Bcrypt",
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
                "Related Module": "formats, network, tokens",
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

with open(f"{WORK_DIR}/reports/batch3_report.md", "w") as f:
    f.write("# Testing Report: Batch 3\n\n")
    for r in reports:
        f.write(f"### {r['Command']}\n")
        f.write(f"**Status:** {r['Status']}\n")
        f.write(f"**Execution Time:** {r['Execution Time']}\n")
        f.write(f"**Root Cause / Error:** {r['Root Cause']}\n")
        f.write("```text\n")
        f.write(r["Result"][:500] + "\n...\n")
        f.write("```\n\n")

print("Batch 3 testing completed. Results saved.")
