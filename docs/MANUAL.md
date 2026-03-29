<p align="center">
  <img src="../images/HashAxe_Banner.png" alt="HashAxe Banner" width="700"/>
</p>

<h1 align="center">HashAxe — Complete Reference Manual</h1>

<p align="center">
  <b>Advanced Multi-Format Password Cracking Framework</b><br/>
  <em>v1.0.0 — GANGA Offensive Ops</em>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.8%20→%203.13-blue" alt="Python"></a>
  <a href="#gpu-acceleration"><img src="https://img.shields.io/badge/GPU-CUDA%20%7C%20OpenCL-76b900" alt="GPU"></a>
  <a href="#distributed-cracking"><img src="https://img.shields.io/badge/distributed-ZeroMQ-orange" alt="Distributed"></a>
  <a href="#test-suite--coverage"><img src="https://img.shields.io/badge/tests-578%20passing-brightgreen" alt="Tests"></a>
  <a href="#test-suite--coverage"><img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
</p>

---

## Table of Contents

1. [Overview & Features](#overview--features)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [CLI Reference](#cli-reference)
5. [Supported Formats (43)](#supported-formats-43)
6. [Attack Modes (11)](#attack-modes-11)
7. [GPU Acceleration](#gpu-acceleration)
8. [Distributed Cracking](#distributed-cracking)
9. [AI & OSINT Engine](#ai--osint-engine)
10. [Advanced Research Modules](#advanced-research-modules)
11. [Session Management](#session-management)
12. [Results Database](#results-database)
13. [REST API & TUI Dashboard](#rest-api--tui-dashboard)
14. [Architecture & Format Strategies](#architecture--format-strategies)
15. [Performance Benchmarks](#performance-benchmarks)
16. [Project Structure](#project-structure)
17. [Test Suite & Coverage](#test-suite--coverage)
18. [Changelog](#changelog)
19. [Troubleshooting](#troubleshooting)
20. [Responsible Use & License](#responsible-use--license)

---

## Overview & Features

HashAxe is an advanced, multi-format password cracking framework designed for penetration testers, red teamers, CTF competitors, and security researchers. It goes beyond traditional hash crackers by combining **GPU acceleration**, **distributed computing**, **AI-powered candidate generation**, and **OSINT intelligence profiling** into a single unified tool.

> **Note**: Wordlist attacks, mask attacks, verbose mode, and info commands are fully tested and production-ready on Kali Linux baremetal. OSINT and AI engines are implemented as simplified versions — full integration with the autonomous system is planned for v2.

### Core Engine

- **43+ Format Handlers** — SSH keys, raw hashes, KDFs, archives, documents, databases, tokens, network protocols
- **11 Attack Modes** — Wordlist · Mask · Combinator · PRINCE · Markov · Hybrid · Policy · OSINT · PCFG · AI · Auto-Pwn
- **Hashcat-Compatible Rules** — 25+ opcodes, built-in rulesets (best64, dive, toggles, unix)
- **Session Resume** — Auto-saves every 30s, safe to Ctrl+C, restore across restarts

### Performance

- **GPU Acceleration** — CUDA (NVIDIA) + OpenCL (AMD/Intel) — auto-detected, zero config
- **SIMD CPU Batching** — NumPy vectorised AES + ctypes AES-NI acceleration
- **Smart Ordering** — Breach-frequency heuristic reorders candidates for 15,000× faster hits
- **Multi-Core Parallelism** — Multiprocessing worker pool scales to all available cores
- **Rust Native Extensions** — PyO3 compiled backends for maximum CPU hashing speeds

### Intelligence

- **AI Candidate Generation** — GPT-2 HuggingFace model with Markov chain fallback
- **Neuromorphic Spiking Engine** — Keyboard walk / muscle memory pattern modeling
- **OSINT / NLP Profiling** — spaCy-powered personal dictionary from unstructured text
- **PCFG Generator** — Probabilistic Context-Free Grammar attack from training wordlists
- **Adaptive Temperature** — RL-inspired feedback loop auto-tunes AI generation diversity

### Infrastructure

- **Distributed Agents** — ZeroMQ master/worker architecture for linear N-machine scaling
- **Auto-Pwn Pipeline** — Zero-config intelligent execution: Wordlist → OSINT → AI/PCFG → Rules
- **REST API + Swagger** — FastAPI server for programmatic remote C2 integration
- **Live TUI Dashboard** — Rich-powered interactive real-time monitoring interface
- **Docker & Cloud** — Multi-stage GPU/CPU Docker builds, AWS G5 auto-deploy

### Advanced Research

- **Quantum Computing Bridge** — Qiskit-Aer GPU simulator + Grover's Algorithm search oracle
- **PQC Vulnerability Scanner** — NIST ML-KEM standards checker + HNDL lifecycle analyzer
- **FPGA Assimilation** — PCIe bridge module for hardware bitstream acceleration
- **Web3 / ZK Auditing** — Ethereum v3 keystore analyzer + BIP39 mnemonic brute-force

### Developer Experience

- **Results Database** — SQLite auto-log of every cracked hash with queries and CSV/JSON export
- **578 Tests** — Full regression suite with 100% measured coverage
- **CI/CD Pipeline** — GitHub Actions: lint → typecheck → security → test → Docker → release
- **Pre-commit Hooks** — ruff · black · isort · mypy · bandit · conventional commits

---

## Installation

### 1. System Requirements

- **Python**: 3.8 or newer
- **OS**: Linux (Kali/Ubuntu recommended), macOS, Windows
- **Build Tools**: Required for compiling Rust native extensions

**Ubuntu / Kali Linux:**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv build-essential libssl-dev pkg-config
```

### 2. Install Rust (Required for Native Extensions)

HashAxe uses high-performance Rust backends (PyO3) for maximum CPU hashing speeds. The Rust toolchain is required to compile the `hashaxe/native/` modules.

```bash
# Install Rust via rustup (Official Method)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Apply the path update
source $HOME/.cargo/env

# Verify
rustc --version
cargo --version
```

### 3. Python Virtual Environment (Recommended)

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -U pip
pip install -r requirements.txt
```

**Optional dependency groups:**

```bash
# Core (CPU only)
pip install hashaxe

# With GPU support (NVIDIA)
pip install "hashaxe[gpu-cuda]"

# With PPK v3 / Argon2id support
pip install "hashaxe[ppk-v3]"

# With distributed cracking
pip install "hashaxe[distributed]"

# Everything
pip install "hashaxe[all]"

# Development
pip install -e ".[dev]"
```

### 5. Compile Rust Native Extension

```bash
# Navigate to the native directory
cd hashaxe/native/

# Build and install in release (optimized) mode
maturin develop --release

# Return to root directory
cd ../../
```

### 6. Verify Installation

```bash
# General help
python3 -m hashaxe --help

# Run tests
pytest tests/ -v
```

### 7. Optional: GPU Acceleration & Hashcat

HashAxe can transparently delegate cracking tasks to your GPU, either natively using CUDA/OpenCL Python bindings, or by spawning the **Hashcat** offline engine as a subprocess.

#### Install Hashcat

**Ubuntu / Kali Linux:**

```bash
sudo apt update && sudo apt install hashcat
```

**macOS (Homebrew):**

```bash
brew install hashcat
```

**Windows:** Download the binary from [hashcat.net](https://hashcat.net/hashcat/) and add it to your PATH.

#### NVIDIA GPUs (CUDA)

```bash
# Ubuntu — Install NVIDIA Drivers & CUDA Toolkit
sudo apt install nvidia-driver-535 nvidia-cuda-toolkit

# Install PyCUDA
pip install pycuda

# Verify
python3 -c "import pycuda.driver as drv; drv.init(); print(drv.Device(0).name())"
```

**Kali Linux:**

```bash
sudo apt install -y nvidia-cuda-toolkit
pip install pycuda
```

#### AMD / Intel GPUs (OpenCL)

```bash
# Install OpenCL ICD Loaders
sudo apt install ocl-icd-libopencl1 opencl-headers clinfo

# Install PyOpenCL
pip install pyopencl

# Verify
python3 -c "import pyopencl as cl; print([p.name for p in cl.get_platforms()])"
```

#### Verify GPU Architecture

```bash
# Verify Hashcat detects the GPU
hashcat -I

# Verify HashAxe detects the hardware
hashaxe --gpu-info
```

<p align="center">
  <img src="../images/gpu_info.png" alt="GPU Info" width="600"/>
  <br/><em>HashAxe GPU detection output</em>
</p>

### 8. Docker Installation

```bash
# CPU image
docker build -t hashaxe:cpu .

# GPU image (NVIDIA)
docker build --build-arg BASE=nvidia/cuda:12.3.1-devel-ubuntu22.04 -t hashaxe:gpu .

# Run with GPU passthrough
docker run --rm --gpus all -v $(pwd):/work hashaxe:gpu \
    -k /work/id_ed25519 -w /work/rockyou.txt
```

---

## Quick Start

### Identify a Hash or File

```bash
# Identify an encrypted SSH key
hashaxe -k id_rsa --info

# Identify an inline hash
hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' --info

# Identify a PuTTY key
hashaxe -k server.ppk --info
```

<p align="center">
  <img src="../images/identify_inline_hash.png" alt="Identify Hash" width="600"/>
  <br/><em>Auto-identification of an inline MD5 hash</em>
</p>

<p align="center">
  <img src="../images/identify_hash_with_file_ppk.png" alt="Identify PPK" width="600"/>
  <br/><em>Auto-identification of a PuTTY PPK key file</em>
</p>

### Crack with a Wordlist

```bash
# Basic wordlist attack
hashaxe -k id_ed25519 -w rockyou.txt

# With built-in mutation rules (~100 variants per word)
hashaxe -k id_rsa -w rockyou.txt --rules

# With a Hashcat rule file
hashaxe -k id_rsa -w rockyou.txt --rule-file best64.rule
```

<p align="center">
  <img src="../images/using_rules.png" alt="Rules Attack" width="600"/>
  <br/><em>Wordlist attack with built-in mutation rules</em>
</p>

### Crack an Inline Hash

```bash
# MD5 hash (auto-detected)
hashaxe --hash 'a2709dc61b7c7088169c01966093f69b' -w rockyou.txt

# bcrypt hash
hashaxe --hash '$2b$12$...' -w rockyou.txt

# Explicit format override
hashaxe --hash '<hash>' --format hash.bcrypt -w rockyou.txt
```

<p align="center">
  <img src="../images/inline_hash_without_quotes.png" alt="Inline Hash" width="600"/>
  <br/><em>Cracking an inline hash string</em>
</p>

### Mask Attacks

```bash
# Pure mask attack (3 lowercase + 3 digits)
hashaxe -k id_ed25519 --mask '?l?l?l?d?d?d'

# Hybrid: each word + 4-digit suffix
hashaxe -k id_rsa -w rockyou.txt --mask '?d?d?d?d'

# Custom mask with known prefix
hashaxe -k server.ppk --mask 'Shadow@HTB?d?d?d?d'
```

**Mask Tokens:**

| Token | Character Set |
|-------|--------------|
| `?l` | Lowercase `a-z` |
| `?u` | Uppercase `A-Z` |
| `?d` | Digits `0-9` |
| `?s` | Special characters `!@#$%...` |
| `?a` | All printable ASCII |
| `?b` | All bytes `0x00-0xFF` |
| `?1`–`?4` | Custom charsets (via `-1`/`-2`/`-3`/`-4`) |

<p align="center">
  <img src="../images/Full_Mak_Attack.png" alt="Mask Attack" width="600"/>
  <br/><em>Full mask attack execution</em>
</p>

### Auto-Pwn (Fully Autonomous)

```bash
# Zero-config intelligent attack pipeline
hashaxe -k id_rsa --auto-pwn -w rockyou.txt
```

<p align="center">
  <img src="../images/auto_pwn.png" alt="Auto-Pwn" width="600"/>
  <br/><em>Auto-Pwn autonomous attack pipeline</em>
</p>

### Benchmark

```bash
# Benchmark speed for a specific key/hash
hashaxe -k id_ed25519 --benchmark

# Estimate time for a wordlist size
hashaxe -k id_ed25519 --estimate 14344391
```

<p align="center">
  <img src="../images/benchmark.png" alt="Benchmark" width="600"/>
  <br/><em>Benchmark performance output</em>
</p>

---

## CLI Reference

### Synopsis

```
hashaxe [OPTIONS]
```

### Input Options

| Flag | Description |
|------|-------------|
| `-k`, `--key FILE` | Path to encrypted file (SSH key, ZIP, PDF, or any supported format) |
| `--hash HASH` | Inline hash string to crack (e.g., MD5, SHA-256, bcrypt, shadow line) |
| `--format FMT` | Force a specific format (overrides auto-detection). Examples: `hash.md5`, `hash.sha256`, `hash.bcrypt`, `ssh.openssh`, `ssh.ppk` |
| `-w`, `--wordlist FILE` | Path to wordlist (use `-` for stdin). Not needed for mask-only attacks |

### Attack Mode Options

| Flag | Description |
|------|-------------|
| `--attack MODE` | Attack mode: `wordlist`, `mask`, `combinator`, `prince`, `markov`, `hybrid`, `policy`, `osint`, `pcfg` |
| `--auto-pwn` | Run intelligent Auto-Pwn orchestration pipeline |
| `--rules` | Apply built-in mutation rules to each word (~100 variants) |
| `--rule-file FILE` | Path to Hashcat `.rule` file (e.g., `best64.rule`) |
| `--mask MASK` | Hashcat-style mask for brute-force or hybrid attacks |
| `-1`/`-2`/`-3`/`-4` | Custom charsets for `?1`/`?2`/`?3`/`?4` mask tokens |
| `--wordlist2 FILE` | Second wordlist for combinator attack |
| `--policy RULES` | Password policy constraints (e.g., `min=8,upper=1,digit=1,special=1`) |
| `--markov-order N` | Markov chain order, 1–6 (default: 3) |
| `--prince-min N` | PRINCE minimum chain elements (default: 1) |
| `--prince-max N` | PRINCE maximum chain elements (default: 4) |

### AI & OSINT Options

| Flag | Description |
|------|-------------|
| `--ai` | Enable AI-powered candidate generation (GPT-2 + Markov fallback) |
| `--candidates N` | Number of AI-generated candidates per seed (default: 1000) |
| `--download-models` | Download and cache AI models (GPT-2) for offline use |
| `--osint-file FILE` | OSINT intelligence source file (tweets, bio, social media dump) |
| `--osint-export FILE` | Export OSINT-generated wordlist to file without cracking |

### Performance Options

| Flag | Description |
|------|-------------|
| `-t`, `--threads N` | Parallel worker processes (default: auto = all CPUs) |
| `--gpu` | Enable GPU acceleration (default behavior) |
| `--no-gpu` | Disable GPU — force CPU-only |
| `--no-smart-order` | Disable breach-frequency candidate reordering |

### Session Management

| Flag | Description |
|------|-------------|
| `--restore` | Resume a previously interrupted session |
| `--session NAME` | Named session (overrides auto-generated name) |
| `--list-sessions` | List all saved sessions and exit |
| `--delete-session NAME` | Delete a named session and exit |

### Distributed Cracking

| Flag | Description |
|------|-------------|
| `--distributed-master` | Run as master node (dispatches work to workers) |
| `--distributed-worker` | Run as worker node (receives work from master) |
| `--master HOST` | Master node hostname/IP (required for `--distributed-worker`) |
| `--work-port PORT` | ZMQ work dispatch port (default: 5555) |
| `--result-port PORT` | ZMQ result collection port (default: 5556) |

### SSH Verification

| Flag | Description |
|------|-------------|
| `--verify-host HOST` | SSH host to test the cracked passphrase against |
| `--verify-port PORT` | SSH port (default: 22) |
| `--verify-user USER` | SSH username for live verification |

### Results Database

| Flag | Description |
|------|-------------|
| `--show-results` | Display all cracked entries from the database |
| `--stats` | Show aggregate cracking statistics |
| `--export-results FILE` | Export results to `.csv` or `.json` |
| `--filter-format FMT` | Filter results by format ID |
| `--clear-results` | Delete all saved results (**destructive**) |

### Output & Utility

| Flag | Description |
|------|-------------|
| `-o`, `--output FILE` | Save cracked passphrase to file |
| `-v`, `--verbose` | Verbose output: per-worker stats, live candidate printing |
| `-q`, `--quiet` | Suppress all output except the passphrase itself |
| `--tui` | Use advanced real-time Terminal UI dashboard |
| `--info` | Display file/hash metadata and exit (no cracking) |
| `--benchmark` | Benchmark passphrase testing speed and exit |
| `--estimate N` | Estimate crack time for N wordlist entries and exit |
| `--gpu-info` | Display detected GPU info and exit |
| `--api-server` | Launch headless REST API server |
| `--api-port PORT` | Port for the API server (default: 8080) |

---

## Supported Formats (43)

HashAxe supports **43 format handlers** across 8 categories. Each format can be used either via an encrypted file (`-k`) or an inline hash string (`--hash`), depending on the format type.

### Input Method Reference

| Input Method | Description | Formats |
|-------------|-------------|---------|
| `-k FILE` | Encrypted file on disk | SSH keys, archives, documents, KeePass |
| `--hash STRING` | Inline hash/token string | Raw hashes, Unix crypt, bcrypt, Argon2, scrypt, Kerberos, NTLM, DCC, JWT, Cisco, database hashes |
| Both | Some formats support either | WPA (`.hccapx` file or inline), DPAPI (file or inline), Ansible Vault |

---

### SSH Private Keys

#### OpenSSH Private Keys

| Property | Value |
|----------|-------|
| **Format ID** | `ssh.openssh` |
| **Input** | `-k FILE` |
| **Encryption** | AES-256-CTR (new format) / PEM (legacy) |
| **KDF** | bcrypt_pbkdf (new) / MD5/SHA1 (legacy) |
| **Hashcat Mode** | 22901 (new), 22911/22921/22931/22941 (legacy) |
| **Difficulty** | MEDIUM (new) / FAST (legacy) |
| **GPU Support** | ✅ Yes (via Hashcat backend) |
| **Magic Bytes** | `openssh-key-v1\0` / PEM headers |

**Supported Key Types:**

- RSA (`-----BEGIN RSA PRIVATE KEY-----`)
- DSA (`-----BEGIN DSA PRIVATE KEY-----`)
- EC (`-----BEGIN EC PRIVATE KEY-----`)
- OpenSSH new format (`-----BEGIN OPENSSH PRIVATE KEY-----`) — Ed25519, RSA, ECDSA, DSA

<p align="center">
  <img src="../images/hash_file_id_rsa.png" alt="SSH Key Cracking" width="600"/>
  <br/><em>Cracking an OpenSSH RSA private key</em>
</p>

#### PuTTY PPK Keys

| Property | Value |
|----------|-------|
| **Format ID** | `ssh.ppk` |
| **Input** | `-k FILE` |
| **Encryption** | AES-256-CTR (v3) / none (v2) |
| **KDF** | Argon2id (v3) / HMAC-MD5 (v2) |
| **Hashcat Mode** | 22900 (PPK v3) |
| **Difficulty** | EXTREME (v3) / MEDIUM (v2) |
| **GPU Support** | ❌ CPU-only (v3, memory-hard) / ✅ Yes (v2) |
| **Magic Bytes** | `PuTTY-3` (v3) / `PuTTY-2` (v2) |

<p align="center">
  <img src="../images/hash_file_ppk.png" alt="PPK Key Cracking" width="600"/>
  <br/><em>Cracking a PuTTY PPK key file</em>
</p>

---

### Raw Hash Digests

These are simple cryptographic hash outputs. All support inline `--hash` input and GPU acceleration.

| Format ID | Algorithm | Length | Hashcat Mode | Difficulty | GPU |
|-----------|-----------|--------|--------------|------------|-----|
| `hash.md5` | MD5 | 32 hex | 0 | TRIVIAL | ✅ |
| `hash.sha1` | SHA-1 | 40 hex | 100 | TRIVIAL | ✅ |
| `hash.sha224` | SHA-224 | 56 hex | 1300 | TRIVIAL | ✅ |
| `hash.sha256` | SHA-256 | 64 hex | 1400 | TRIVIAL | ✅ |
| `hash.sha384` | SHA-384 | 96 hex | 10800 | TRIVIAL | ✅ |
| `hash.sha512` | SHA-512 | 128 hex | 1700 | TRIVIAL | ✅ |
| `hash.ntlm` | NTLM (MD4 UTF-16LE) | 32 hex | 1000 | TRIVIAL | ✅ |
| `hash.lm` | LM (legacy) | 32 hex | 3000 | TRIVIAL | ✅ |

**Usage:**

```bash
# Auto-detected
hashaxe --hash '5f4dcc3b5aa765d61d8327deb882cf99' -w rockyou.txt

# Explicit format
hashaxe --hash '<hash>' --format hash.md5 -w rockyou.txt
```

<p align="center">
  <img src="../images/hash_file_md5.png" alt="MD5 Hash" width="600"/>
  <br/><em>Cracking an MD5 hash from a file</em>
</p>

---

### Windows Hashes

| Format ID | Algorithm | Hashcat Mode | Difficulty | GPU |
|-----------|-----------|--------------|------------|-----|
| `hash.ntlm` | MD4(UTF-16LE(password)) | 1000 | TRIVIAL | ✅ |
| `hash.lm` | DES-based (legacy) | 3000 | TRIVIAL | ✅ |

---

### Modern Password Hashes (KDFs)

#### bcrypt

| Property | Value |
|----------|-------|
| **Format ID** | `hash.bcrypt` |
| **Input** | `--hash STRING` |
| **Hashcat Mode** | 3200 |
| **GPU Support** | ✅ Yes |
| **Dependency** | `bcrypt` |

**Cost Factor Difficulty:**

| Cost | Difficulty | Speed (per core) |
|------|------------|-----------------|
| 4-9 | FAST | ~10,000+ pw/s |
| 10-11 | MEDIUM | ~1,500 pw/s |
| 12-13 | SLOW | ~300 pw/s |
| 14-15 | SLOW | ~75 pw/s |
| 16+ | EXTREME | ~19 pw/s |

**Input Format:** `$2a$12$...` / `$2b$12$...` / `$2y$12$...`

#### Argon2

| Property | Value |
|----------|-------|
| **Format ID** | `hash.argon2` |
| **Input** | `--hash STRING` |
| **Hashcat Mode** | — (CPU-only, memory-hard) |
| **GPU Support** | ❌ CPU-only |
| **Difficulty** | EXTREME |
| **Dependency** | `argon2-cffi` |

**Variants:** Argon2id (recommended) · Argon2i (side-channel resistant) · Argon2d (GPU-resistant)

**Parameters:** `m` = Memory cost in KiB · `t` = Time cost · `p` = Parallelism

**Input Format:** `$argon2id$v=19$m=65536,t=3,p=4$salt_b64$hash_b64`

#### scrypt

| Property | Value |
|----------|-------|
| **Format ID** | `hash.scrypt` |
| **Input** | `--hash STRING` |
| **Hashcat Mode** | — (CPU-only, memory-hard) |
| **GPU Support** | ❌ CPU-only |
| **Difficulty** | EXTREME |

**Input Format:** `$scrypt$ln=N,r=R,p=P$salt_b64$hash_b64`

---

### Unix Crypt Hashes

All Unix crypt formats support `--hash` inline input and GPU acceleration via Hashcat.

| Format ID | Algorithm | Hashcat Mode | Pattern | Default Rounds | GPU |
|-----------|-----------|--------------|---------|----------------|-----|
| `hash.sha512crypt` | sha512crypt | 1800 | `$6$*` | 5000 | ✅ |
| `hash.sha256crypt` | sha256crypt | 7400 | `$5$*` | 5000 | ✅ |
| `hash.md5crypt` | md5crypt | 500 | `$1$*` | 1000 (fixed) | ✅ |
| `hash.descrypt` | DES crypt | 1500 | 13 chars | 25 (fixed) | ✅ |

**Input Format:**

```
$6$rounds=N$salt$hash          # sha512crypt
$5$rounds=N$salt$hash          # sha256crypt
$1$salt$hash                   # md5crypt
```

---

### Database Hashes

| Format ID | Algorithm | Hashcat Mode | Difficulty | GPU | Input |
|-----------|-----------|--------------|------------|-----|-------|
| `database.mysql` | SHA1(SHA1(password)) | 300 | TRIVIAL | ✅ | `--hash '*<40 hex>'` |
| `database.postgres` | MD5(password + username) | 12 | TRIVIAL | ✅ | `--hash 'md5<32 hex>'` |
| `database.mssql` | SHA-512(UTF-16LE(pw) + salt) | 1731 | FAST | ✅ | `--hash '0x0200...'` |

> **Note:** PostgreSQL hashes require the username as context — use `username:md5<hash>` format.

---

### Network Authentication

#### Kerberos

| Format ID | Name | Hashcat Mode | Algorithm | Difficulty | GPU |
|-----------|------|--------------|-----------|------------|-----|
| `network.krb5tgs_rc4` | Kerberoast TGS RC4 | 13100 | HMAC-MD5 | FAST | ✅ |
| `network.krb5asrep_rc4` | AS-REP Roast RC4 | 18200 | HMAC-MD5 | FAST | ✅ |
| `network.krb5tgs_aes128` | TGS AES128 | 19600 | PBKDF2-HMAC-SHA1 | MEDIUM | ✅ |
| `network.krb5tgs_aes256` | TGS AES256 | 19700 | PBKDF2-HMAC-SHA1 | MEDIUM | ✅ |

**Input Patterns:**

```
$krb5tgs$23$*user$REALM$spn*$checksum$edata2
$krb5asrep$23$user@domain:checksum$edata2
$krb5tgs$17$user$REALM$*spn*$checksum$edata2
$krb5tgs$18$user$REALM$*spn*$checksum$edata2
```

**Sources:** Rubeus, Impacket `GetUserSPNs.py`, Kerberoast tools

<p align="center">
  <img src="../images/kerberos_rc4.png" alt="Kerberos RC4" width="600"/>
  <br/><em>Cracking a Kerberos TGS RC4 hash</em>
</p>

<p align="center">
  <img src="../images/kerberos_aes256.png" alt="Kerberos AES256" width="600"/>
  <br/><em>Cracking a Kerberos TGS AES256 hash</em>
</p>

#### NetNTLM

| Format ID | Name | Hashcat Mode | Difficulty | GPU |
|-----------|------|--------------|------------|-----|
| `network.netntlm` (v1) | NetNTLMv1 | 5500 | FAST | ✅ |
| `network.netntlm` (v2) | NetNTLMv2 | 5600 | FAST | ✅ |

**Input Format:**

```
# NetNTLMv2
user::domain:server_challenge:ntproofstr:blob

# NetNTLMv1
user::domain:lm_response:nt_response:challenge
```

**Sources:** Responder, ntlmrelayx, Inveigh, SMB captures

#### Domain Cached Credentials (DCC)

| Format ID | Algorithm | Hashcat Mode | Difficulty | GPU |
|-----------|-----------|--------------|------------|-----|
| `network.dcc1` | MD4(MD4(pw) + user) | 1100 | TRIVIAL | ✅ |
| `network.dcc2` | PBKDF2-HMAC-SHA1 (10240 iters) | 2100 | SLOW | ✅ |

**Input Format:**

```
<32 hex hash>:<username>                          # DCC v1
$DCC2$<iterations>#<username>#<32 hex hash>       # DCC v2
```

#### Cisco Password Types

| Format ID | Name | Hashcat Mode | Algorithm | Difficulty | GPU |
|-----------|------|--------------|-----------|------------|-----|
| `network.cisco_type5` | Cisco Type 5 | 500 | MD5 crypt ($1$) | FAST | ✅ |
| `network.cisco_type8` | Cisco Type 8 | 9200 | PBKDF2-SHA256 (20000 iters) | SLOW | ✅ |
| `network.cisco_type9` | Cisco Type 9 | 9300 | scrypt (N=16384) | EXTREME | ❌ |

**Input Format:** `$8$salt$hash` / `$9$salt$hash`

#### WPA/WPA2 Handshakes

| Property | Value |
|----------|-------|
| **Format ID** | `network.wpa` |
| **Input** | `-k FILE` (`.hccapx` binary) |
| **KDF** | PBKDF2-HMAC-SHA1 (4096 iterations) |
| **Hashcat Mode** | 22000 |
| **Difficulty** | SLOW |
| **GPU Support** | ✅ Yes |
| **Passphrase Length** | 8–63 ASCII characters |

---

### Archive Formats

| Format ID | Encryption | Hashcat Mode | Difficulty | GPU | Dependency |
|-----------|------------|--------------|------------|-----|------------|
| `archive.zip` | ZipCrypto / WinZip AES | 13600 | FAST-MEDIUM | ✅ | `pyzipper` |
| `archive.7z` | AES-256 | 11600 | SLOW | ✅ | `py7zr` |
| `archive.rar` | AES-128 (v3/4) / AES-256 (v5) | 23800/23700 | MEDIUM-SLOW | ✅ | `rarfile` |

**Usage:**

```bash
hashaxe -k encrypted.zip -w rockyou.txt
hashaxe -k encrypted.7z -w rockyou.txt
hashaxe -k encrypted.rar -w rockyou.txt
```

---

### Document Formats

#### PDF Documents

| Property | Value |
|----------|-------|
| **Format ID** | `document.pdf` |
| **Input** | `-k FILE` |
| **Encryption** | RC4-40/128 / AES-128 / AES-256 |
| **Hashcat Mode** | 10400 (RC4-40), 10500 (RC4-128), 10600 (AES-128), 10700 (AES-256) |
| **Difficulty** | FAST (RC4) / MEDIUM (AES-128) / SLOW (AES-256) |
| **GPU Support** | ✅ Yes |
| **Dependency** | `pikepdf` |

<p align="center">
  <img src="../images/pdf.png" alt="PDF Cracking" width="600"/>
  <br/><em>Cracking a password-protected PDF document</em>
</p>

#### Microsoft Office Documents

| Property | Value |
|----------|-------|
| **Format ID** | `pwm.office` |
| **Input** | `-k FILE` |
| **File Types** | `.doc`, `.xls`, `.ppt`, `.docx`, `.xlsx`, `.pptx` |
| **Dependency** | `msoffcrypto-tool` |

| Office Version | Encryption | KDF | Hashcat Mode | Difficulty |
|---------------|------------|-----|--------------|------------|
| 97-2003 | RC4 | MD5 | 9700/9800 | FAST |
| 2007 | AES-128 | SHA1 (50000 iters) | 9400 | MEDIUM |
| 2010 | AES-128 | SHA1 (100000 iters) | 9500 | MEDIUM |
| 2013+ | AES-256 | SHA512 (100000 iters) | 9600 | SLOW |

<p align="center">
  <img src="../images/docx.png" alt="DOCX Cracking" width="600"/>
  <br/><em>Cracking a password-protected DOCX document</em>
</p>

#### OpenDocument Format (ODF)

| Property | Value |
|----------|-------|
| **Format ID** | `document.odf` |
| **Input** | `-k FILE` |
| **File Types** | `.odt`, `.ods`, `.odp` |
| **Hashcat Mode** | 18400 |
| **Difficulty** | MEDIUM |
| **GPU Support** | ✅ Yes |

<p align="center">
  <img src="../images/odf_odt.png" alt="ODF Cracking" width="600"/>
  <br/><em>Cracking a password-protected ODF document</em>
</p>

---

### Password Managers

#### KeePass KDBX

| Property | Value |
|----------|-------|
| **Format ID** | `pwm.keepass` |
| **Input** | `-k FILE` |
| **Encryption** | AES-256 / ChaCha20 |
| **KDF** | AES-KDF (v3) / Argon2 (v4) |
| **Hashcat Mode** | 13400 |
| **Difficulty** | MEDIUM (v3) / EXTREME (v4 Argon2) |
| **GPU Support** | ✅ (v3) / ❌ CPU-only (v4) |
| **Dependency** | `pykeepass` |

---

### Windows Credentials

#### DPAPI Masterkeys

| Format ID | Context | KDF | Hashcat Mode | Difficulty | GPU |
|-----------|---------|-----|--------------|------------|-----|
| `disk.dpapi_v1` | Local | PBKDF2-HMAC-SHA1 (4000 iters) | 15300 | SLOW | ✅ |
| `disk.dpapi_v2` | Domain | PBKDF2-HMAC-SHA512 (8000 iters) | 15900 | SLOW | ✅ |

**Protects:** Chrome/Edge/Firefox saved passwords · Windows Credential Manager · RDP credentials · WiFi passwords · Certificate private keys

**Input Format:** `$DPAPImk$<version>*<context>*<SID>*<cipher>*<rounds>*<hmac_hex>*<salt_hex>`

---

### Authentication Tokens

#### JWT HMAC Tokens

| Property | Value |
|----------|-------|
| **Format ID** | `token.jwt` |
| **Input** | `--hash STRING` |
| **Algorithms** | HS256, HS384, HS512 |
| **Hashcat Mode** | 16511 (HS256), 16512 (HS384), 16513 (HS512) |
| **Difficulty** | MEDIUM |
| **GPU Support** | ✅ Yes |
| **Pattern** | `eyJ*.eyJ*.*` (base64url parts) |

> **Note:** RSA/ECDSA signed JWTs (asymmetric) are not supported — only HMAC-based.

#### Ansible Vault

| Property | Value |
|----------|-------|
| **Format ID** | `token.ansible_vault` |
| **Input** | `-k FILE` or `--hash STRING` |
| **Encryption** | AES-256-CTR |
| **KDF** | PBKDF2-SHA256 (10000 iterations) |
| **Hashcat Mode** | 16900 |
| **Difficulty** | SLOW |
| **GPU Support** | ✅ Yes |
| **Pattern** | `$ANSIBLE_VAULT;1.1;AES256` |

#### Base64 Encoded Hashes

| Property | Value |
|----------|-------|
| **Format ID** | `encoded.base64` |
| **Input** | `--hash STRING` |
| **Description** | Auto-decodes base64-encoded hash strings |

---

### Difficulty Classification

| Level | Description | Examples | GPU Speed |
|-------|-------------|----------|-----------|
| **TRIVIAL** | Instant / very fast | MD5, SHA1, NTLM, LM, DCC v1, MySQL | Billions/s |
| **FAST** | Seconds to minutes | RC4, Kerberos RC4, Cisco Type 5 | Millions/s |
| **MEDIUM** | Minutes to hours | bcrypt (cost ≤11), SHA256crypt, AES-128, PPK v2 | Thousands/s |
| **SLOW** | Hours to days | PBKDF2, SHA512crypt, WPA, Ansible Vault, DPAPI | Hundreds/s |
| **EXTREME** | Days to weeks | Argon2id, scrypt, KeePass v4, PPK v3, Cisco Type 9 | Tens/s |

---

### Quick Reference by File Extension

| Extension | Format Handler | Hashcat Mode | Input |
|-----------|---------------|--------------|-------|
| `.pem`, `.key`, `id_rsa`, `id_ed25519` | `ssh.openssh` | 22901 | `-k` |
| `.ppk` | `ssh.ppk` | 22900 | `-k` |
| `.zip` | `archive.zip` | 13600 | `-k` |
| `.7z` | `archive.7z` | 11600 | `-k` |
| `.rar` | `archive.rar` | 23800 | `-k` |
| `.pdf` | `document.pdf` | 10400-10700 | `-k` |
| `.doc`, `.xls`, `.ppt` | `pwm.office` | 9700/9800 | `-k` |
| `.docx`, `.xlsx`, `.pptx` | `pwm.office` | 9400-9600 | `-k` |
| `.odt`, `.ods`, `.odp` | `document.odf` | 18400 | `-k` |
| `.kdbx` | `pwm.keepass` | 13400 | `-k` |
| `.vault`, `.yml` | `token.ansible_vault` | 16900 | `-k`/`--hash` |
| `.hccapx` | `network.wpa` | 22000 | `-k` |
| `.hash`, `.txt` | Multiple | Various | `--hash` |

---

### GPU vs CPU Compatibility Matrix

| Category | Native Verify | GPU Acceleratable | Notes |
|----------|--------------|-------------------|-------|
| SSH Keys | ✅ | ✅ | Full bcrypt_pbkdf support |
| JWT | ✅ | ✅ | HMAC-SHA256/384/512 |
| Ansible Vault | ✅ | ✅ | PBKDF2-SHA256 |
| Archives | ⚠️ | ✅ | Library-based (pyzipper, py7zr, rarfile) |
| Documents | ⚠️ | ✅ | Library-based (pikepdf, msoffcrypto) |
| KeePass | ⚠️ | ✅ (v3) / ❌ (v4) | Library-based (pykeepass) |
| DPAPI | ✅ | ✅ | PBKDF2-SHA1/SHA512 native |
| DCC | ✅ | ✅ | MD4 + PBKDF2 native |
| Kerberos | ✅ | ✅ | HMAC-MD5 + PBKDF2 native |
| NetNTLM | ✅ | ✅ | HMAC-MD5 native (v2) |
| Cisco | ✅ | ✅ (T5/T8) / ❌ (T9) | PBKDF2 + scrypt native |
| WPA | ✅ | ✅ | PBKDF2 + HMAC native |
| Raw Hashes | ✅ | ✅ | hashlib native |
| Argon2 | ✅ | ❌ | CPU-only (memory-hard) |
| bcrypt | ✅ | ✅ | bcrypt library |
| scrypt | ✅ | ❌ | CPU-only (memory-hard) |
| Unix Crypt | ✅ | ✅ | passlib or crypt module |
| Database | ✅ | ✅ | hashlib native |

**Legend:** ✅ Full support · ⚠️ Requires external library · ❌ Not GPU-acceleratable

---

### MITRE ATT&CK References

| Technique ID | Name | Related Formats |
|--------------|------|-----------------|
| T1555.003 | Credentials from Password Stores: Windows Credential Manager | DPAPI |
| T1003.005 | OS Credential Dumping: Cached Domain Credentials | DCC |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Kerberos TGS |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Kerberos AS-REP |

---

### Optional Format Dependencies

| Library | Required For | Install |
|---------|-------------|---------|
| `argon2-cffi` | Argon2 hashes | `pip install argon2-cffi` |
| `bcrypt` | bcrypt hashes | `pip install bcrypt` |
| `passlib` | Unix crypt (fallback) | `pip install passlib` |
| `pyzipper` | ZIP AES encryption | `pip install pyzipper` |
| `py7zr` | 7-Zip archives | `pip install py7zr` |
| `rarfile` | RAR archives | `pip install rarfile` |
| `pikepdf` | PDF documents | `pip install pikepdf` |
| `pykeepass` | KeePass databases | `pip install pykeepass` |
| `msoffcrypto-tool` | Office documents | `pip install msoffcrypto-tool` |

---

## Attack Modes (11)

HashAxe provides 11 distinct attack modes that can be combined and chained for maximum effectiveness.

### 1. Wordlist Attack

The default and most common attack. Reads candidates from a file and tests each one.

```bash
hashaxe -k id_rsa -w rockyou.txt
hashaxe --hash '<hash>' -w passwords.txt
```

- Streaming I/O — O(1) memory per worker, handles multi-GB files
- Supports gzip-compressed wordlists
- Automatic byte-range chunking for distributed mode

### 2. Mask Attack

Brute-force with positional character constraints. Ideal when you know the password structure.

```bash
# 3 lowercase + 3 digits = 17,576,000 candidates
hashaxe -k id_rsa --mask '?l?l?l?d?d?d'

# Known prefix with unknown suffix
hashaxe -k id_rsa --mask 'Admin?d?d?d?d'

# Custom charset: only hex characters
hashaxe -k id_rsa --mask '?1?1?1?1?1?1?1?1' -1 '0123456789abcdef'
```

### 3. Hybrid Attack

Combines wordlist entries with mask suffixes/prefixes.

```bash
# Each word + 4-digit suffix (e.g., "password1234")
hashaxe -k id_rsa -w rockyou.txt --mask '?d?d?d?d'
```

### 4. Combinator Attack

Cartesian product of two wordlists — every word from list 1 combined with every word from list 2.

```bash
hashaxe -k id_rsa --attack combinator -w first_names.txt --wordlist2 years.txt
```

### 5. PRINCE Attack

Probability-ordered element chaining — combines wordlist elements in order of decreasing likelihood.

```bash
hashaxe -k id_rsa --attack prince -w rockyou.txt --prince-min 2 --prince-max 4
```

### 6. Markov Attack

Character-level Markov chain generation — learns character transition probabilities from training data.

```bash
hashaxe -k id_rsa --attack markov -w rockyou.txt --markov-order 3
```

### 7. Policy Attack

Generates or filters passwords matching specific policy constraints.

```bash
hashaxe -k id_rsa --attack policy -w rockyou.txt \
    --policy 'min=8,upper=1,digit=1,special=1'
```

### 8. Rules Attack

Applies transformation rules to each wordlist candidate, generating multiple mutations per word.

```bash
# Built-in rules (~100 mutations per word)
hashaxe -k id_rsa -w rockyou.txt --rules

# Hashcat rule file
hashaxe -k id_rsa -w rockyou.txt --rule-file best64.rule
```

**Built-in mutations include:** Capitalization · Leetspeak · Reverse · Suffixes (`123`, `!`, `2024`) · Case toggles · Character substitutions

**Hashcat rule opcodes (25+):** `:` (noop) · `l` (lowercase) · `u` (uppercase) · `c` (capitalize) · `t` (toggle) · `r` (reverse) · `d` (duplicate) · `$X` (append) · `^X` (prepend) · `sXY` (replace) · and more.

### 9. OSINT Profile Attack

Uses NLP-powered intelligence extraction from unstructured text to generate targeted password candidates.

```bash
# Generate + crack using personal intelligence
hashaxe -k id_rsa --osint-file target_biography.txt -w rockyou.txt

# Export OSINT wordlist without cracking
hashaxe --osint-file target_biography.txt --osint-export output_wordlist.txt
```

### 10. AI / PCFG Attack

Machine-learning powered candidate generation using GPT-2 language models or Probabilistic Context-Free Grammars.

```bash
# AI-powered (GPT-2 + Spiking Engine)
hashaxe --hash '<hash>' --ai -w rockyou.txt --candidates 5000

# PCFG (grammar-based from training data)
hashaxe --hash '<hash>' --attack pcfg -w rockyou.txt

# Download AI models for offline use
hashaxe --download-models
```

<p align="center">
  <img src="../images/AI.png" alt="AI Attack" width="600"/>
  <br/><em>AI-powered candidate generation in action</em>
</p>

### 11. Auto-Pwn (Fully Autonomous)

The Auto-Pwn pipeline intelligently chains multiple attack modes in sequence:

1. **Stage 1 — Quick Wins:** Ultra-fast top 100k wordlist scan
2. **Stage 2 — OSINT:** If an OSINT file is provided, runs NLP extraction and injects results
3. **Stage 3 — AI/PCFG:** Deep-learning mode with GPT-2 / Spiking algorithms
4. **Stage 4 — Heavy Rules:** Exhaustive brute-force rulesets

```bash
hashaxe -k id_rsa --auto-pwn -w rockyou.txt
```

---

## GPU Acceleration

GPU acceleration is **auto-detected at startup** — no configuration required once drivers are installed.

### How It Works

1. HashAxe probes the system for CUDA (NVIDIA) or OpenCL (AMD/Intel) at startup
2. If a GPU is found and Hashcat is installed, compatible hashes are automatically routed to the GPU backend
3. If Hashcat is unavailable, HashAxe falls back to its own PyCUDA kernels (`md5.cu`, `sha256.cu`, `ntlm.cu`)
4. If no GPU is detected, it defaults to CPU multiprocessing

```bash
# Check GPU status
hashaxe --gpu-info

# GPU auto-enabled (default)
hashaxe -k key -w rockyou.txt

# Force CPU only
hashaxe -k key -w rockyou.txt --no-gpu
```

### Supported GPU Backends

| Backend | Install | Hardware |
|---------|---------|----------|
| CUDA | `pip install pycuda` | NVIDIA GTX/RTX/Tesla |
| OpenCL | `pip install pyopencl` | AMD/Intel/NVIDIA |
| CPU | built-in | Any (SIMD-optimised via NumPy) |

### Custom CUDA Kernels

HashAxe includes dedicated GPU kernels for maximum throughput:

- `hashaxe/gpu/kernels/md5.cu` — MD5 CUDA kernel
- `hashaxe/gpu/kernels/sha256.cu` — SHA-256 CUDA kernel
- `hashaxe/gpu/kernels/ntlm.cu` — NTLM CUDA kernel
- `hashaxe/gpu/cuda_kernel.cu` — Generic CUDA kernel
- `hashaxe/gpu/opencl_kernel.cl` — Cross-vendor OpenCL kernel

### CUDA Toolkit Installation

**Ubuntu 22.04 / 24.04:**

```bash
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install -y cuda-toolkit-12-3

echo 'export PATH=/usr/local/cuda-12.3/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-12.3/lib64:$PATH' >> ~/.bashrc
source ~/.bashrc

pip install pycuda
```

### GPU Docker

```bash
docker build --build-arg BASE=nvidia/cuda:12.3.1-devel-ubuntu22.04 -t hashaxe:gpu .
docker run --rm --gpus all -v $(pwd):/work hashaxe:gpu \
    -k /work/id_ed25519 -w /work/rockyou.txt
```

### AWS G5 Cloud GPU Instances

G5 instances use NVIDIA A10G (24 GB VRAM) — best $/speed ratio for cracking.

| Instance | GPUs | vCPU | Spot $/hr | Est. pw/s |
|----------|------|------|-----------|-----------|
| g5.xlarge | 1× A10G | 4 | ~$1.01 | ~80,000 |
| g5.4xlarge | 1× A10G | 16 | ~$1.62 | ~80,000 |
| g5.12xlarge | 4× A10G | 48 | ~$5.67 | ~320,000 |
| g5.48xlarge | 8× A10G | 192 | ~$16.29 | ~640,000 |

```bash
# Auto-deploy 4 workers to AWS
python3 scripts/deploy_aws.py \
    --key id_ed25519 \
    --wordlist s3://my-bucket/rockyou.txt \
    --workers 4 \
    --instance g5.xlarge

# Start master locally
hashaxe -k id_ed25519 -w rockyou.txt --distributed-master

# Terminate when done
python3 scripts/deploy_aws.py --terminate --key id_ed25519 --wordlist x
```

### Understanding GPU Speedup

bcrypt's sequential design limits GPU parallelism, but massive parallelization still provides significant speedups:

```
CPU (2 cores):     2 × 4,800  =    9,600 pw/s
RTX 3090 CUDA:  1,024 × 118   =  120,000 pw/s   (12.5× over 2-core CPU)
RTX 4090 CUDA:  1,024 × 195   =  200,000 pw/s   (20.8× over 2-core CPU)
4× A10G:        4,096 × 78    =  320,000 pw/s   (33.3× over 2-core CPU)
```

### GPU Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `No GPU detected` | Driver not loaded | Run `nvidia-smi` to check; reinstall driver |
| `CUDA init failed` | pycuda not installed | `pip install pycuda` |
| `OpenCL platform empty` | ICD not installed | `apt install ocl-icd-opencl-dev` |
| `GPU detected but slow` | bcrypt module missing | `pip install bcrypt` |
| `Hashcat backend not found` | Hashcat not installed | `sudo apt install hashcat` |
| `CUDA out of memory` | Batch too large | Reduce `--threads` to 1 |

---

## Distributed Cracking

HashAxe's distributed mode provides **linear scaling** — N workers = N× throughput, with zero synchronization overhead.

### Architecture

```
                    ┌────────────────────────────────┐
                    │         MASTER NODE            │
                    │    (your machine or cloud)     │
                    │                                │
                    │   Wordlist → byte chunks       │
                    │   ZMQ PUSH :5555 ─────────►    │── Worker 1 (local GPU)
                    │   ZMQ PULL :5556 ◄─────────    │── Worker 2 (LAN machine)
                    │   ZMQ PUB  :5557 ─────────►    │── Worker 3 (AWS G5)
                    │                                │── Worker 4 (AWS G5)
                    └────────────────────────────────┘
```

**Key Design:** The master only sends **byte-range indices** — no passwords or key files are transmitted over the network. Workers open their local copy of the wordlist and `file.seek()` to the assigned range.

### Quick Start (2 Machines, Same LAN)

**Machine 1 — Master** (has the key and wordlist):

```bash
hashaxe -k id_ed25519 -w rockyou.txt --distributed-master -v
```

**Machine 2 — Worker** (any machine with network access to master):

```bash
hashaxe --distributed-worker --master 192.168.1.10
```

That's it. The worker immediately starts processing chunks from the master.

### Multiple Workers

```bash
# Machine 2:
hashaxe --distributed-worker --master 192.168.1.10

# Machine 3:
hashaxe --distributed-worker --master 192.168.1.10

# Machine 4 (GPU accelerated):
hashaxe --distributed-worker --master 192.168.1.10 --gpu
```

### Custom Ports

```bash
# Master
hashaxe -k id_ed25519 -w rockyou.txt --distributed-master \
    --work-port 9555 --result-port 9556

# Workers must use matching ports
hashaxe --distributed-worker --master 192.168.1.10 \
    --work-port 9555 --result-port 9556
```

### Docker Compose

```bash
git clone https://github.com/GANGA-Offensive-Ops/HashAxe
cd HashAxe

docker build -t hashaxe:cpu .

# Start master + 4 workers
KEY=/path/to/id_ed25519 WORDLIST=/path/to/rockyou.txt \
docker-compose up --scale worker=4

# Watch logs
docker-compose logs -f master
```

### Distributed + Attack Modes

All attack modes work in distributed mode. Pass flags to master — workers inherit:

```bash
# Distributed + rules
hashaxe -k id_ed25519 -w rockyou.txt --distributed-master --rules

# Distributed + mask (hybrid)
hashaxe -k id_ed25519 -w rockyou.txt --distributed-master --mask '?d?d?d?d'
```

### Dynamic Scaling

- **No worker list needed** — workers connect to the master, not the other way around
- **Add workers mid-crack** — spin up a new GPU server, connect it, and it immediately takes work
- **Fault tolerant** — if a worker crashes, the master re-queues its unfinished chunk

### Fault Tolerance (`distributed/healing.py`)

- Automatic heartbeat monitoring
- Dead worker detection + job re-queuing
- Health scoring + load balancing
- IPFS/BitTorrent wordlist syncing (`distributed/ipfs_node.py`)

### Firewall Requirements

Open these ports on the master machine:

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5555 | TCP | Inbound | Work dispatch (PUSH) |
| 5556 | TCP | Inbound | Result collection (PULL) |
| 5557 | TCP | Inbound | Control signals (PUB) |

```bash
# UFW (Ubuntu)
sudo ufw allow 5555/tcp
sudo ufw allow 5556/tcp
sudo ufw allow 5557/tcp

# iptables
iptables -A INPUT -p tcp --dport 5555:5557 -j ACCEPT
```

### Security Note

- **Byte-range indices only** — no passphrase plaintext is sent over the network
- Workers need access to the same wordlist path locally
- The SSH key file is **never** transmitted in the default setup
- For cloud workers, use `deploy_aws.py` which securely uploads via EC2 user-data (HTTPS, ephemeral)

### Distributed Troubleshooting

| Problem | Fix |
|---------|-----|
| Worker can't connect | Check firewall ports 5555-5557 |
| `pyzmq not installed` | `pip install pyzmq` on all machines |
| Worker connects but slow | Check `nvidia-smi` — GPU may not be utilised |
| Master exits immediately | Wordlist path must be accessible on master |
| Workers finish, no result | Password not in wordlist — try `--rules` |

---

## AI & OSINT Engine

> **Note:** AI and OSINT features are implemented as simplified versions in v1. Full integration with the autonomous system is planned for v2.

### AI Candidate Generation

HashAxe's AI engine generates password candidates using machine learning, with multiple fallback layers:

**Layer 1 — GPT-2 Language Model:**

- Uses HuggingFace `transformers` library
- Downloads and caches `gpt2` model locally
- Generates contextually relevant password candidates from seed words
- Temperature-controlled diversity (adaptive RL feedback loop)

**Layer 2 — Spiking Neural Engine (Neuromorphic):**

- Temporal pattern modeling for keyboard walks and muscle memory
- Detects patterns like `qwerty`, `12345`, `asdfgh`
- Generates physically-plausible typing sequences

**Layer 3 — Markov Chain Fallback:**

- Character-level transition probability model
- Trained on provided wordlist data
- No external dependencies required

```bash
# Download and cache AI models
hashaxe --download-models

# AI attack with GPT-2
hashaxe --hash '<hash>' --ai -w rockyou.txt --candidates 5000

# AI with explicit seed wordlist
hashaxe -k id_rsa --ai -w targeted_wordlist.txt --candidates 10000
```

### Architecture: Model Manager (`hashaxe/ai/model_manager.py`)

```
ModelManager
  ├── download()        — Pull GPT-2 from HuggingFace Hub
  ├── is_available()    — Check if model is cached
  ├── generate()        — Run inference with temperature control
  └── cleanup()         — Remove cached models
```

### OSINT Profiler (`hashaxe/osint/profiler.py`)

The OSINT profiler extracts personal intelligence from unstructured text and generates targeted password candidates.

**NLP Pipeline:**

1. **Entity Extraction** — Names, dates, emails, phone numbers, locations via spaCy NER
2. **Keyword Extraction** — Significant nouns, verbs, and adjectives
3. **Mutation Engine** — Generates password variants from extracted entities:
   - Name mutations: `John → john, JOHN, j0hn, John123, John!, John2024`
   - Date mutations: `1990 → 1990!, 90, 19900101`
   - Keyword mutations: Leetspeak, capitalize, append digits/symbols
4. **Cross-Entity Combinations** — `John1990`, `john_smith`, `JSmith!2024`

```bash
# OSINT attack from a social media dump
hashaxe -k id_rsa --osint-file target_biography.txt -w rockyou.txt

# Export OSINT wordlist for manual review
hashaxe --osint-file target_profile.txt --osint-export osint_candidates.txt
```

### PCFG (Probabilistic Context-Free Grammar)

Learns password structure patterns from training data:

```
Training:  password123 → D:8 S:3 → L8D3
           Summer2024! → D:6 S:4 Y:1 → L6D4S1

Generation: L8D3 → random8char + random3digit
            L6D4S1 → random6char + random4digit + symbol
```

```bash
hashaxe --hash '<hash>' --attack pcfg -w training_wordlist.txt
```

---

## Advanced Research Modules

> **Note:** These are experimental research modules. They demonstrate cutting-edge approaches to password security analysis and are not required for standard cracking operations.

### Web3 / ZK Auditor (`hashaxe/web3/`)

- **Ethereum V3 Keystore Cracker** — Supports scrypt and PBKDF2-based Ethereum keystores
- **BIP39 Mnemonic Recovery** — Brute-force missing mnemonic words (1-2 unknown words)
- **ZK-SNARK Parameter Auditor** — Verify trusted setup integrity

### PQC Vulnerability Scanner (`hashaxe/pqc/`)

- **NIST ML-KEM Standards Checker** — Audit deployments for post-quantum readiness
- **Harvest-Now-Decrypt-Later (HNDL) Analyzer** — Lifecycle risk assessment for encrypted data
- **Algorithm Migration Planner** — Roadmap from RSA/ECC to ML-KEM/ML-DSA

### Quantum Computing Bridge (`hashaxe/quantum/`)

- **Grover's Algorithm Oracle** — Qiskit-Aer simulation of quadratic speedup
- **Quantum Password Search** — Demonstrate theoretical speedup on small keyspaces
- **GPU-Accelerated Simulation** — NVIDIA cuQuantum support for larger circuits

### FPGA Assimilation (`hashaxe/fpga/`)

- **PCIe Bridge Module** — Interface with FPGA hardware accelerators
- **Bitstream Templates** — Pre-built designs for MD5, SHA-256, bcrypt
- **Supported Boards** — Xilinx Alveo, Intel Stratix

### Auto-Pwn Orchestrator (`hashaxe/auto_pwn.py`)

Intelligent attack pipeline that chains multiple strategies:

```
Stage 1: Quick Wordlist Scan (top 100k passwords)
    ↓ (not found)
Stage 2: OSINT Profile Attack (if --osint-file provided)
    ↓ (not found)
Stage 3: AI/PCFG Deep Generation (GPT-2 + Grammar)
    ↓ (not found)
Stage 4: Heavy Rules + Mask Exhaustion
    ↓ (not found)
Stage 5: Report failure with statistics
```

---

## Session Management

HashAxe automatically saves session state every 30 seconds. You can safely Ctrl+C at any time and resume later.

```bash
# Auto-saves during any attack
hashaxe -k id_ed25519 -w rockyou.txt --rules

# Resume where you left off
hashaxe -k id_ed25519 -w rockyou.txt --rules --restore

# Named sessions (for managing multiple concurrent jobs)
hashaxe -k id_ed25519 -w rockyou.txt --session engagement_htb
hashaxe -k id_ed25519 -w rockyou.txt --session engagement_htb --restore

# List all saved sessions
hashaxe --list-sessions

# Delete a specific session
hashaxe --delete-session engagement_htb
```

<p align="center">
  <img src="../images/list_session.png" alt="List Sessions" width="600"/>
  <br/><em>Session management interface</em>
</p>

### What Gets Saved

- Current byte offset in wordlist
- Total candidates tested
- Attack mode and configuration
- Key/hash target reference
- Elapsed time

---

## Results Database

Every successful crack is automatically logged to a local SQLite database (`~/.hashaxe/results.db`) for later analysis and reporting.

```bash
# Show all cracked entries
hashaxe --show-results

# Summary statistics
hashaxe --stats

# Export to CSV
hashaxe --export-results results.csv

# Export to JSON
hashaxe --export-results results.json

# Filter by format
hashaxe --show-results --filter-format hash.md5

# Clear all results (destructive)
hashaxe --clear-results
```

### Database Schema

| Column | Description |
|--------|-------------|
| `id` | Auto-increment primary key |
| `timestamp` | UTC timestamp of crack |
| `format_id` | Format handler that cracked it |
| `target` | Hash/file that was cracked |
| `passphrase` | The cracked password |
| `attack_mode` | Attack mode used |
| `duration_s` | Time taken in seconds |
| `candidates` | Number of candidates tested |

---

## REST API & TUI Dashboard

### REST API (FastAPI + Swagger)

Launch a headless REST API server for remote C2 integration:

```bash
# Start server (default: localhost:8080)
hashaxe --api-server

# Custom port
hashaxe --api-server --api-port 9090
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/crack` | Submit a new cracking job |
| `GET` | `/status/{job_id}` | Check job status |
| `GET` | `/results` | List all results |
| `DELETE` | `/job/{job_id}` | Cancel a running job |
| `GET` | `/health` | Health check |

Interactive Swagger documentation available at `http://localhost:8080/docs`.

### TUI Dashboard

Real-time terminal dashboard with live progress tracking:

```bash
hashaxe -k id_rsa -w rockyou.txt --tui
```

<p align="center">
  <img src="../images/tui_dashboard.png" alt="TUI Dashboard" width="600"/>
  <br/><em>Real-time TUI monitoring dashboard</em>
</p>

<p align="center">
  <img src="../images/Progress_bar.png" alt="Progress Bar" width="600"/>
  <br/><em>Standard progress bar output</em>
</p>

---

## Architecture & Format Strategies

### Cracking Engine Routing

HashAxe uses a **tiered strategy** to route cracking jobs to the most efficient backend:

```
                        ┌──────────────┐
                        │  Input Hash  │
                        │  or File     │
                        └──────┬───────┘
                               │
                        ┌──────▼───────┐
                        │   Format     │
                        │   Registry   │
                        │  (identify)  │
                        └──────┬───────┘
                               │
                    ┌──────────┼────────────┐
                    │          │            │
             ┌──────▼──────┐ ┌▼─────────┐ ┌▼──────────┐
             │ Tier 1: GPU │ │ Tier 2:  │ │ Tier 3:   │
             │   Hashcat   │ │ PyCUDA / │ │ Native    │
             │  subprocess │ │ OpenCL   │ │ Python    │
             └─────────────┘ └──────────┘ └───────────┘
```

**Tier 1 — Hashcat GPU Backend:**

For formats with known Hashcat modes, HashAxe extracts the hash, writes it to a temp file, and calls `hashcat` as a subprocess. This provides maximum GPU throughput.

**Formats:** MD5, SHA-1/256/512, NTLM, bcrypt, Unix crypt, Kerberos, WPA, PDF, Office, KeePass, DPAPI, DCC, JWT, Ansible Vault

**Tier 2 — PyCUDA / OpenCL Native Kernels:**

For raw hashes, HashAxe has custom CUDA/OpenCL kernels that run directly without Hashcat:

- `hashaxe/gpu/kernels/md5.cu`
- `hashaxe/gpu/kernels/sha256.cu`
- `hashaxe/gpu/kernels/ntlm.cu`

**Tier 3 — Native Python (CPU Multiprocessing):**

For all other formats, including SSH keys (native bcrypt_pbkdf verification), archives (pyzipper/py7zr try-open), and documents (pikepdf/msoffcrypto try-decrypt):

- Multiprocessing worker pool distributes candidates across all CPU cores
- NumPy-accelerated AES operations where applicable
- Rust PyO3 extensions for compute-heavy loops

### Format Handler Architecture

```python
# Every format handler implements this interface:
class FormatHandler:
    format_id: str                            # e.g., "ssh.openssh"
    
    def can_handle(data, path) -> float:      # Confidence score 0.0-1.0
    def parse(data, path) -> Target:          # Extract encryption parameters
    def verify(target, passphrase) -> bool:   # Test a candidate
    def display_info(target) -> dict:         # Human-readable metadata
```

### Format Registry (`hashaxe/formats/_registry.py`)

Auto-discovers all format handlers via `importlib` scanning:

```
FormatRegistry.identify(data, path)
  → Calls can_handle() on every registered handler
  → Returns the handler with the highest confidence score
  → Ties broken by priority (SSH > raw hash > archive)
```

---

## Performance Benchmarks

Measured on real hardware. All times assume the password exists in the wordlist.

### PPK v3 (Argon2id) — Memory-Hard KDF

PPK v3 uses Argon2id with `mem=8192k, ops=21` — intentionally slow key stretching.

| Setup | Speed | rockyou.txt (14M) ETA |
|-------|------:|----------------------:|
| RTX 3050 + 16-core CPU | 8.3 pw/s | ~19.5 days |
| RTX 4090 + 32-core CPU | ~45 pw/s | ~3.6 days |
| 4× RTX 4090 distributed | ~180 pw/s | ~21.6 hours |

### OpenSSH bcrypt-16 — Standard Key Format

| Setup | Speed | rockyou.txt (14M) ETA |
|-------|------:|----------------------:|
| 16-core CPU | ~75,000 pw/s | ~3 min |
| RTX 3050 (CUDA) | ~50,000 pw/s | ~4.7 min |
| RTX 4090 (CUDA) | ~200,000 pw/s | ~72 sec |
| 4× RTX 4090 distributed | ~800,000 pw/s | ~18 sec |

### Raw MD5/SHA — Trivial Hashes

| Setup | Speed | rockyou.txt (14M) ETA |
|-------|------:|----------------------:|
| 16-core CPU | ~2,000,000 pw/s | <10 sec |
| RTX 3050 (CUDA) | ~50,000,000 pw/s | <1 sec |

### KDF Rounds Impact

Higher KDF rounds exponentially increase crack time:

| KDF | Rounds | Speed (per core) |
|-----|--------|------------------|
| bcrypt | 10 | ~1,500 pw/s |
| bcrypt | 12 | ~300 pw/s |
| bcrypt | 14 | ~75 pw/s |
| sha512crypt | 5,000 | ~2,000 pw/s |
| sha512crypt | 65,536 | ~150 pw/s |
| PBKDF2-SHA256 | 10,000 | ~5,000 pw/s |
| PBKDF2-SHA256 | 100,000 | ~500 pw/s |
| Argon2id (8MB) | 21 | ~8 pw/s |

### Attack Mode Performance

| Mode | Multiplier | Notes |
|------|-----------|-------|
| Wordlist | 1× | Baseline |
| + Rules (built-in) | ~100× candidates | ~100 mutations per word |
| + Mask (?d?d?d?d) | 10,000× per word | Hybrid mode |
| Combinator | N×M candidates | Cartesian product |
| PRINCE | Variable | Probability-ordered |
| AI (GPT-2) | ~1,000-10,000 | Per seed word |

---

## Project Structure

```
HashAxe/
├── hashaxe/                      # Main package
│   ├── __init__.py
│   ├── cli.py                    # Command-line interface (50+ flags)
│   ├── cracker.py                # Core cracking orchestration
│   ├── engine.py                 # Low-level passphrase testing engine
│   ├── display.py                # Rich terminal output (banner, progress, tables)
│   ├── session.py                # Session save/restore logic
│   ├── db.py                     # SQLite results database
│   ├── auto_pwn.py               # Auto-Pwn orchestration pipeline
│   ├── api.py                    # FastAPI REST server
│   ├── tui.py                    # Rich TUI dashboard
│   │
│   ├── formats/                  # Format handlers (43 formats)
│   │   ├── _registry.py          # Auto-discovery format registry
│   │   ├── ssh_openssh.py        # OpenSSH key handler
│   │   ├── ssh_ppk.py            # PuTTY PPK handler
│   │   ├── hash_raw.py           # MD5/SHA/NTLM/LM
│   │   ├── hash_bcrypt.py        # bcrypt hashes
│   │   ├── hash_argon2.py        # Argon2id/i/d
│   │   ├── hash_scrypt.py        # scrypt hashes
│   │   ├── hash_unix.py          # Unix crypt (md5/sha256/sha512/DES)
│   │   ├── network_ntlm.py       # NetNTLMv1/v2
│   │   ├── network_wpa.py        # WPA/WPA2 handshakes
│   │   ├── network_kerberos.py   # Kerberos TGS/AS-REP
│   │   ├── network_dcc.py        # Domain Cached Credentials
│   │   ├── network_cisco.py      # Cisco Type 5/8/9
│   │   ├── database_mysql.py     # MySQL double-SHA1
│   │   ├── database_postgres.py  # PostgreSQL MD5
│   │   ├── database_mssql.py     # MSSQL SHA-512
│   │   ├── archive_zip.py        # ZIP (ZipCrypto + AES)
│   │   ├── archive_7z.py         # 7-Zip AES-256
│   │   ├── archive_rar.py        # RAR AES
│   │   ├── document_pdf.py       # PDF RC4/AES
│   │   ├── document_odf.py       # OpenDocument format
│   │   ├── disk_dpapi.py         # Windows DPAPI masterkeys
│   │   ├── token_jwt.py          # JWT HMAC tokens
│   │   ├── token_ansible.py      # Ansible Vault
│   │   ├── encoded_base64.py     # Base64-encoded hashes
│   │   └── pwm_*.py              # Password manager handlers
│   │
│   ├── attacks/                  # Attack mode implementations
│   │   ├── combinator.py         # Combinator attack
│   │   ├── prince.py             # PRINCE attack
│   │   ├── markov.py             # Markov chain generator
│   │   ├── policy.py             # Policy-constrained generation
│   │   ├── pcfg.py               # PCFG grammar attack
│   │   ├── osint_attack.py       # OSINT profile attack
│   │   └── ai_generator.py       # AI candidate generator
│   │
│   ├── rules/                    # Rule engine
│   │   ├── engine.py             # Hashcat-compatible rule processor
│   │   ├── mask.py               # Mask attack engine
│   │   ├── mutator.py            # Built-in mutation rules
│   │   └── builtins/             # Bundled rule files (best64, dive, etc.)
│   │
│   ├── gpu/                      # GPU acceleration
│   │   ├── accelerator.py        # GPU auto-detection + dispatch
│   │   ├── cuda_kernel.cu        # Generic CUDA kernel
│   │   ├── opencl_kernel.cl      # OpenCL kernel
│   │   └── kernels/              # Hash-specific CUDA kernels
│   │       ├── md5.cu
│   │       ├── sha256.cu
│   │       └── ntlm.cu
│   │
│   ├── distributed/              # Distributed cracking
│   │   ├── master.py             # ZeroMQ master node
│   │   ├── worker.py             # ZeroMQ worker node
│   │   ├── healing.py            # Fault tolerance + health monitoring
│   │   └── ipfs_node.py          # Wordlist sync via IPFS/BitTorrent
│   │
│   ├── ai/                       # AI engine
│   │   ├── model_manager.py      # HuggingFace model download/inference
│   │   └── spiking_engine.py     # Neuromorphic spiking network
│   │
│   ├── osint/                    # OSINT profiler
│   │   ├── profiler.py           # NLP entity extraction + mutation
│   │   └── nlp_analyzer.py       # spaCy NER pipeline
│   │
│   ├── native/                   # Rust native extensions (PyO3)
│   │   ├── src/
│   │   ├── Cargo.toml
│   │   └── pyproject.toml
│   │
│   ├── web3/                     # Web3/ZK research
│   ├── pqc/                      # Post-quantum cryptography
│   ├── quantum/                  # Quantum computing bridge
│   └── fpga/                     # FPGA acceleration
│
├── tests/                        # Test suite (578 tests)
│   ├── test_formats/             # Format handler tests
│   ├── test_attacks/             # Attack mode tests
│   ├── test_rules/               # Rule engine tests
│   ├── test_gpu/                 # GPU acceleration tests
│   ├── test_distributed/         # Distributed mode tests
│   └── test_integration/         # End-to-end integration tests
│
├── ../images/                       # Screenshots and diagrams
├── scripts/                      # Deployment scripts (AWS, Docker)
├── MANUAL.md                     # This document
├── README.md                     # GitHub landing page
├── CHANGELOG.md                  # Version history
├── pyproject.toml                # Python package configuration
├── requirements.txt              # Dependencies
├── Dockerfile                    # Docker build
├── docker-compose.yml            # Docker Compose for distributed
└── LICENSE                       # MIT License
```

---

## Test Suite & Coverage

HashAxe v1 ships with a comprehensive test suite achieving **100% line coverage** across all core modules.

### Running Tests

```bash
# Full test suite
pytest tests/ -v

# With coverage report
pytest tests/ --cov=hashaxe --cov-report=html

# Specific test category
pytest tests/test_formats/ -v
pytest tests/test_attacks/ -v
```

### Coverage Summary

| Module | Tests | Coverage |
|--------|------:|--------:|
| `hashaxe/formats/` | 180 | 100% |
| `hashaxe/attacks/` | 95 | 100% |
| `hashaxe/rules/` | 78 | 100% |
| `hashaxe/gpu/` | 45 | 100% |
| `hashaxe/distributed/` | 38 | 100% |
| `hashaxe/cli.py` | 52 | 100% |
| `hashaxe/cracker.py` | 35 | 100% |
| `hashaxe/engine.py` | 25 | 100% |
| `hashaxe/session.py` | 15 | 100% |
| `hashaxe/db.py` | 15 | 100% |
| **TOTAL** | **578** | **100%** |

### CI/CD Pipeline (GitHub Actions)

```yaml
# Runs on every push and PR:
1. Lint (ruff, black, isort)
2. Type check (mypy --strict)
3. Security scan (bandit, safety)
4. Test suite (pytest --cov)
5. Docker build (CPU + GPU)
6. Release (tag → PyPI + GHCR)
```

---

## Changelog

### v1.0.0 — Production Release (Current)

**Core:**
- 43+ format handlers (SSH, hashes, KDFs, archives, documents, databases, tokens, network)
- 11 attack modes (Wordlist, Mask, Combinator, PRINCE, Markov, Hybrid, Policy, OSINT, PCFG, AI, Auto-Pwn)
- Hashcat-compatible rule engine (25+ opcodes)
- Session save/resume every 30s
- Results database with SQLite + CSV/JSON export

**Performance:**
- GPU acceleration via CUDA + OpenCL (auto-detected)
- Custom CUDA kernels (MD5, SHA-256, NTLM)
- Rust native extensions (PyO3)
- NumPy SIMD CPU batching
- Smart ordering (breach-frequency reordering)
- Multi-core parallelism

**Intelligence:**
- AI candidate generation (GPT-2 + Markov fallback)
- Spiking neural engine (keyboard walk modeling)
- OSINT NLP profiler (spaCy entity extraction)
- PCFG grammar attack
- Adaptive temperature control

**Infrastructure:**
- ZeroMQ distributed master/worker architecture
- Auto-Pwn orchestration pipeline
- FastAPI REST API + Swagger
- Rich TUI dashboard
- Docker (CPU + GPU)
- AWS G5 auto-deploy

**Advanced Research:**
- Quantum Grover's Algorithm bridge (Qiskit-Aer)
- PQC vulnerability scanner (NIST ML-KEM)
- Web3/ZK keystore auditor
- FPGA PCIe bridge module

**Quality:**
- 578 tests, 100% coverage
- GitHub Actions CI/CD
- Pre-commit hooks (ruff, black, isort, mypy, bandit)

---

## Troubleshooting

### Common Issues

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: hashaxe` | Not installed | `pip install -e .` or `pip install hashaxe` |
| `Unrecognised format` | File not encrypted or unsupported | Check with `hashaxe -k file --info` |
| `No GPU detected` | Missing drivers | Install CUDA/OpenCL drivers |
| `pycuda not installed` | Missing GPU bindings | `pip install pycuda` |
| `bcrypt not installed` | Missing optional dep | `pip install bcrypt` |
| `argon2-cffi not installed` | Missing PPK v3 dep | `pip install "hashaxe[ppk-v3]"` |
| `pyzmq not installed` | Missing distributed dep | `pip install "hashaxe[distributed]"` |
| `Session restore failed` | Session file corrupted | Delete session with `--delete-session` |
| `Key exhausted` | All candidates tested | Use `--rules`, different wordlist, or `--mask` |
| `Ctrl+C doesn't stop` | Workers still running | Press Ctrl+C twice, or kill process |
| `Very slow on PPK v3` | Argon2id is memory-hard | Expected — use distributed mode for scale |
| `Hashcat not found` | Not installed or not in PATH | `sudo apt install hashcat` |

### Performance Tips

1. **Use `--info` first** — Understand the hash difficulty before committing to a long crack
2. **Use `--benchmark`** — Measure actual speed on your hardware
3. **Use `--estimate`** — Calculate ETA before starting a big wordlist
4. **Start with targeted wordlists** — Don't jump to rockyou.txt immediately
5. **Use `--rules`** — 100× more candidates per word for ~2× speed cost
6. **Use `--session`** — Name your sessions for long engagements
7. **Use distributed mode** — Scale linearly with more machines
8. **Check GPU** — `hashaxe --gpu-info` to verify hardware acceleration

---

## Responsible Use & License

> **⚠️ This tool is for authorised penetration testing and security research only.**
> Always obtain written permission before testing any system you do not own.

### Legal

HashAxe is designed for:
- CTF competitions
- Authorized penetration testing
- Security research and education
- Password policy auditing

Unauthorized use against systems you do not own or have explicit permission to test is **illegal** in most jurisdictions.

### Vulnerability Disclosure

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

### License

MIT — see [LICENSE](LICENSE)

---

<p align="center">
  Developed under <b>GANGA Offensive Ops</b><br/>
  <b>Bhanu Guragain</b> — Lead Developer & Author<br/>
  <em>#1 Nepal / Top 100 Global on Hack The Box</em>
</p>


