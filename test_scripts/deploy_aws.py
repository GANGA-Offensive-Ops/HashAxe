#!/usr/bin/env python3
# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: scripts/deploy_aws.py
#  AWS G5 spot instance auto-deployment for distributed HASHAXE workers.
#  Provisions GPU workers with CUDA, wordlists, and hashaxe configuration.
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
scripts/deploy_aws.py — Auto-deploy hashaxe workers on AWS G5 spot instances.

** Note This File is not tested test and run as needed **

Usage:
    # Deploy 4 G5.xlarge workers (4 vCPU, 1× NVIDIA A10G each)
    python3 scripts/deploy_aws.py \\
        --key id_ed25519 \\
        --wordlist rockyou.txt \\
        --workers 4 \\
        --instance g5.xlarge

    # Use g5.12xlarge for 4× A10G per instance (best $/hashaxe)
    python3 scripts/deploy_aws.py \\
        --key id_ed25519 \\
        --wordlist s3://my-bucket/rockyou.txt \\
        --workers 2 \\
        --instance g5.12xlarge \\
        --spot-price 3.50

Speed estimates (A10G GPU, 16 rounds bcrypt):
    g5.xlarge   (1× A10G, 4  vCPU) → ~80,000 pw/s   @ ~$1.006/hr spot
    g5.4xlarge  (1× A10G, 16 vCPU) → ~80,000 pw/s   @ ~$1.624/hr spot
    g5.12xlarge (4× A10G, 48 vCPU) → ~320,000 pw/s  @ ~$5.672/hr spot
    g5.48xlarge (8× A10G, 192 vCPU)→ ~640,000 pw/s  @ ~$16.288/hr spot

Cost example — 14M rockyou.txt @ 320,000 pw/s:
    43 seconds × $5.672/hr = $0.07 total

Requires:
    pip install boto3 paramiko
    AWS credentials configured (aws configure)
    IAM role with: EC2, SSM, S3 read permissions
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# ── User data script injected into each EC2 instance ─────────────────────────

_USER_DATA_TEMPLATE = """#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Install dependencies
apt-get update -q
apt-get install -y -q python3-pip python3-dev libssl-dev libffi-dev git

# Install NVIDIA CUDA (for G5 instances)
if command -v nvidia-smi &>/dev/null; then
    pip3 install pycuda --quiet || true
fi

# Install hashaxe
pip3 install pyzmq numpy cryptography --quiet
git clone --depth 1 https://github.com/GANGAOps/HashAxe /opt/hashaxe
cd /opt/hashaxe && pip3 install -e . --quiet

# Download wordlist from S3 if path starts with s3://
WORDLIST="{wordlist}"
if [[ "$WORDLIST" == s3://* ]]; then
    pip3 install awscli --quiet
    aws s3 cp "$WORDLIST" /tmp/wordlist.txt
    WORDLIST=/tmp/wordlist.txt
fi

# Upload key to instance via SSM / userdata (base64 encoded)
echo "{key_b64}" | base64 -d > /tmp/target.key
chmod 600 /tmp/target.key

# Start worker
MASTER_IP="{master_ip}"
nohup hashaxe --distributed-worker --master "$MASTER_IP" \\
    >> /var/log/hashaxe-worker.log 2>&1 &

echo "Worker started — PID: $!"
"""

# ── Deployment manager ────────────────────────────────────────────────────────


class AWSDeployer:

    def __init__(
        self,
        key_path: str,
        wordlist: str,
        n_workers: int = 4,
        instance_type: str = "g5.xlarge",
        spot_price: float = 2.0,
        region: str = "us-east-1",
        master_ip: str | None = None,
        dry_run: bool = False,
    ):
        self.key_path = key_path
        self.wordlist = wordlist
        self.n_workers = n_workers
        self.instance_type = instance_type
        self.spot_price = spot_price
        self.region = region
        self.master_ip = master_ip
        self.dry_run = dry_run
        self._instances: list[str] = []

    def deploy(self) -> str | None:
        """
        Deploy workers and return master public IP.
        Returns None on dry-run or error.
        """
        try:
            import boto3
        except ImportError:
            print("[!] boto3 required: pip install boto3")
            return None

        ec2 = boto3.client("ec2", region_name=self.region)

        # Read and encode the key file
        key_bytes = Path(self.key_path).read_bytes()
        key_b64 = base64.b64encode(key_bytes).decode()

        # Determine master IP (assume we're running on master)
        master_ip = self.master_ip or self._get_public_ip()

        print(f"[*] Deploying {self.n_workers}× {self.instance_type} workers")
        print(f"    Master: {master_ip}:5555-5557")
        print(f"    Wordlist: {self.wordlist}")
        print(f"    Spot bid: ${self.spot_price}/hr")

        if self.dry_run:
            print("[*] DRY RUN — no instances launched.")
            return master_ip

        # Build user data
        user_data = _USER_DATA_TEMPLATE.format(
            wordlist=self.wordlist,
            key_b64=key_b64,
            master_ip=master_ip,
        )
        user_data_b64 = base64.b64encode(user_data.encode()).decode()

        # Launch spot instances
        resp = ec2.request_spot_instances(
            InstanceCount=self.n_workers,
            SpotPrice=str(self.spot_price),
            LaunchSpecification={
                "ImageId": self._get_ami(ec2),
                "InstanceType": self.instance_type,
                "UserData": user_data_b64,
                "Monitoring": {"Enabled": False},
                "TagSpecifications": [
                    {
                        "ResourceType": "spot-instances-request",
                        "Tags": [
                            {"Key": "Name", "Value": "hashaxe-worker"},
                            {"Key": "Project", "Value": "hashaxe"},
                        ],
                    }
                ],
            },
        )

        request_ids = [r["SpotInstanceRequestId"] for r in resp["SpotInstanceRequests"]]
        print(f"[+] {len(request_ids)} spot requests submitted: {request_ids}")

        # Wait for fulfilment
        print("[*] Waiting for instances (max 3 minutes)...")
        self._instances = self._wait_for_instances(ec2, request_ids)

        if self._instances:
            print(f"[+] {len(self._instances)} workers running: {self._instances}")
            self._open_firewall(ec2, master_ip)
        else:
            print("[!] Some instances did not start — check AWS console.")

        return master_ip

    def terminate(self) -> None:
        """Terminate all deployed worker instances."""
        if not self._instances:
            return
        try:
            import boto3

            ec2 = boto3.client("ec2", region_name=self.region)
            ec2.terminate_instances(InstanceIds=self._instances)
            print(f"[+] Terminated: {self._instances}")
        except Exception as exc:
            print(f"[!] Terminate error: {exc}")

    def _get_ami(self, ec2) -> str:
        """Get the latest Ubuntu 22.04 AMI for the current region."""
        resp = ec2.describe_images(
            Owners=["099720109477"],  # Canonical
            Filters=[
                {
                    "Name": "name",
                    "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"],
                },
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
                {"Name": "virtualization-type", "Values": ["hvm"]},
            ],
        )
        images = sorted(resp["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if not images:
            raise ValueError("No Ubuntu 22.04 AMI found in region")
        return images[0]["ImageId"]

    def _wait_for_instances(self, ec2, request_ids: list[str]) -> list[str]:
        """Wait up to 3 minutes for spot requests to be fulfilled."""
        instance_ids = []
        deadline = time.time() + 180
        while time.time() < deadline:
            resp = ec2.describe_spot_instance_requests(
                SpotInstanceRequestIds=request_ids,
            )
            fulfilled = [
                r["InstanceId"]
                for r in resp["SpotInstanceRequests"]
                if r["State"] == "active" and r.get("InstanceId")
            ]
            if len(fulfilled) == len(request_ids):
                return fulfilled
            time.sleep(10)
        return instance_ids

    def _get_public_ip(self) -> str:
        """Get this machine's public IP address."""
        try:
            import urllib.request

            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            return "127.0.0.1"

    def _open_firewall(self, ec2, master_ip: str) -> None:
        """Open ZMQ ports 5555-5557 on the master's security group."""
        # This is a best-effort helper — may fail if SG is already configured
        try:
            ec2.authorize_security_group_ingress(
                GroupId="default",
                IpProtocol="tcp",
                FromPort=5555,
                ToPort=5557,
                CidrIp="0.0.0.0/0",
            )
        except Exception:
            pass  # Already open or no permission — user handles manually


# ── CLI ───────────────────────────────────────────────────────────────────────


def main():
    p = argparse.ArgumentParser(description="Deploy hashaxe workers on AWS G5 spot instances")
    p.add_argument("--key", required=True, help="SSH key to hashaxe")
    p.add_argument("--wordlist", required=True, help="Wordlist path (local or s3://)")
    p.add_argument("--workers", type=int, default=4, help="Number of GPU workers")
    p.add_argument("--instance", default="g5.xlarge", help="EC2 instance type")
    p.add_argument("--spot-price", type=float, default=2.0, help="Max spot price $/hr")
    p.add_argument("--region", default="us-east-1", help="AWS region")
    p.add_argument("--master-ip", default=None, help="Override master IP")
    p.add_argument("--terminate", action="store_true", help="Terminate all workers")
    p.add_argument("--dry-run", action="store_true", help="Print plan without deploying")

    args = p.parse_args()

    deployer = AWSDeployer(
        key_path=args.key,
        wordlist=args.wordlist,
        n_workers=args.workers,
        instance_type=args.instance,
        spot_price=args.spot_price,
        region=args.region,
        master_ip=args.master_ip,
        dry_run=args.dry_run,
    )

    if args.terminate:
        deployer.terminate()
    else:
        master_ip = deployer.deploy()
        if master_ip:
            print(f"\n[+] Workers deployed. Start master:")
            print(f"    hashaxe -k {args.key} -w {args.wordlist} --distributed-master")
            print(
                f"\n[!] When done: python3 scripts/deploy_aws.py --terminate --key {args.key} --wordlist x"
            )


if __name__ == "__main__":
    main()
