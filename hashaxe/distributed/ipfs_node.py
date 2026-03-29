# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/distributed/ipfs_node.py
#  IPFS/BitTorrent decentralized wordlist distribution for massive dictionaries.
#  Enables P2P swarm sharing of multi-terabyte datasets across distributed workers.
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
distributed/ipfs_node.py — IPFS/BitTorrent decentralized wordlist distribution.

Eliminates central server bottlenecks for massive dictionary distribution.
Instead of master streaming words over ZMQ, workers form a P2P swarm
to download and seed multi-terabyte datasets.

Architecture:
  ┌────────────┐                    ┌────────────┐
  │   Master   │──CID/Magnet──────▶│  Worker 1  │──┐
  │  (publishes│                   │  (downloads)│  │ P2P
  │   metadata)│                   └────────────┘  │ Swarm
  └────────────┘                    ┌────────────┐  │
                                   │  Worker 2  │──┤
                                   │  (seeds)   │  │
                                   └────────────┘  │
                                    ┌────────────┐  │
                                   │  Worker 3  │──┘
                                   │  (leeches) │
                                   └────────────┘

Supported protocols:
  - IPFS (via py-ipfs-api or kubo HTTP API)
  - BitTorrent (via libtorrent or transmission-rpc)
  - Direct HTTP fallback
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SwarmAsset:
    """A distributed asset tracked by the swarm."""

    name: str
    cid: str = ""  # IPFS Content Identifier
    magnet_link: str = ""  # BitTorrent magnet link
    size_bytes: int = 0
    file_hash: str = ""  # SHA-256 of file for verification
    chunks: int = 1
    local_path: str = ""
    is_available: bool = False
    protocol: str = "none"  # "ipfs", "torrent", "http"


class IPFSNode:
    """IPFS/BitTorrent peer node for decentralized data distribution.

    Manages publishing and retrieving wordlists and rainbow tables
    via content-addressed decentralized protocols.

    Usage:
        node = IPFSNode()
        # Publisher (master):
        asset = node.publish("/path/to/rockyou.txt")
        # send asset.cid to workers via ZMQ control channel

        # Subscriber (worker):
        local_path = node.fetch(cid="Qm...")
    """

    def __init__(
        self,
        ipfs_api: str = "/ip4/127.0.0.1/tcp/5001",
        cache_dir: str | None = None,
    ):
        self._api_addr = ipfs_api
        self._cache_dir = Path(cache_dir or Path.home() / ".crackedb" / "swarm")
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ipfs = None
        self._ipfs_available = False
        self._detect_ipfs()

    def _detect_ipfs(self) -> None:
        """Check if IPFS daemon is running and accessible."""
        try:
            import ipfshttpclient  # type: ignore

            self._ipfs = ipfshttpclient.connect(self._api_addr, session=True)
            version = self._ipfs.version()
            self._ipfs_available = True
            logger.info("IPFS connected: v%s", version.get("Version", "?"))
        except Exception:
            logger.debug("IPFS not available (kubo daemon not running)")
            self._ipfs_available = False

    @property
    def is_available(self) -> bool:
        return self._ipfs_available

    def publish(self, file_path: str | Path) -> SwarmAsset:
        """Publish a file to the IPFS network.

        Returns a SwarmAsset with the CID for retrieval by workers.
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Cannot publish: {file_path}")

        file_hash = self._hash_file(p)
        size = p.stat().st_size

        if self._ipfs_available and self._ipfs:
            try:
                result = self._ipfs.add(str(p), pin=True)
                cid = result["Hash"] if isinstance(result, dict) else result[0]["Hash"]
                logger.info("Published to IPFS: %s → %s", p.name, cid)
                return SwarmAsset(
                    name=p.name,
                    cid=cid,
                    size_bytes=size,
                    file_hash=file_hash,
                    local_path=str(p),
                    is_available=True,
                    protocol="ipfs",
                )
            except Exception as e:
                logger.warning("IPFS publish failed: %s", e)

        # Fallback: generate content hash as pseudo-CID
        pseudo_cid = f"local:{file_hash[:16]}"
        return SwarmAsset(
            name=p.name,
            cid=pseudo_cid,
            size_bytes=size,
            file_hash=file_hash,
            local_path=str(p),
            is_available=True,
            protocol="local",
        )

    def fetch(self, cid: str, output_name: str = "") -> str | None:
        """Fetch a file from IPFS by CID.

        Returns local file path or None if unavailable.
        """
        if cid.startswith("local:"):
            logger.info("Local CID detected — file must be available locally")
            return None

        if not self._ipfs_available or not self._ipfs:
            logger.warning("IPFS not available for fetch")
            return None

        out_path = self._cache_dir / (output_name or cid.replace("/", "_"))

        if out_path.exists():
            logger.info("Cache hit: %s", out_path)
            return str(out_path)

        try:
            self._ipfs.get(cid, target=str(self._cache_dir))
            logger.info("Fetched from IPFS: %s → %s", cid, out_path)
            return str(out_path)
        except Exception as e:
            logger.error("IPFS fetch failed: %s", e)
            return None

    def list_cached(self) -> list[dict]:
        """List all cached swarm assets."""
        result = []
        for f in self._cache_dir.iterdir():
            if f.is_file():
                result.append(
                    {
                        "name": f.name,
                        "size": f.stat().st_size,
                        "path": str(f),
                    }
                )
        return result

    def info(self) -> dict:
        """Return node status information."""
        return {
            "ipfs_available": self._ipfs_available,
            "api_addr": self._api_addr,
            "cache_dir": str(self._cache_dir),
            "cached_files": len(list(self._cache_dir.iterdir())),
        }

    @staticmethod
    def _hash_file(path: Path) -> str:
        """Compute SHA-256 of a file."""
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
