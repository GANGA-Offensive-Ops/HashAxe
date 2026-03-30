<p align="center">
  <img src="images/HashAxe_Banner.png" alt="HashAxe Banner" width="700"/>
</p>

<h1 align="center">HashAxe V1 Advanced Password Cracker</h1>

<p align="center">
  <b>Multi-Format Hash & Password Recovery Framework Auto-Detecting 43+ Formats for Pentesters, Red Teams, and CTF Players</b><br/>
  <em>43+ Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI/JWT/Sha/md5 ++</em><br/>
  <em>GPU-Accelerated · Distributed · AI-Powered · Auto-Pwn</em>
</p>

<p align="center">
  <a href="https://github.com/GANGA-Offensive-Ops/HashAxe/actions"><img src="https://img.shields.io/github/actions/workflow/status/GANGA-Offensive-Ops/Hashaxe/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="docs/MANUAL.md#test-suite--coverage"><img src="https://img.shields.io/badge/tests-578%20passing-brightgreen" alt="Tests"></a>
  <a href="docs/MANUAL.md#test-suite--coverage"><img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Coverage"></a>
  <a href="docs/MANUAL.md#gpu-acceleration"><img src="https://img.shields.io/badge/GPU-CUDA%20%7C%20OpenCL-76b900" alt="GPU"></a>
  <a href="docs/MANUAL.md#distributed-cracking"><img src="https://img.shields.io/badge/distributed-ZeroMQ-orange" alt="Distributed"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.8%20→%203.13-blue" alt="Python"></a>
</p>

---

> **⚡ Project Status:** Core features: Auto-detects, wordlist attacks, mask attacks, verbose mode, info commands, rules, and session management are fully tested and production-ready on Kali Linux baremetal. AI and OSINT engines ship as simplified implementations; full integration with our autonomous offensive system is planned for v2. This tool is built for CTF players, pentesting students, and security professionals.

---

## Features

| Category | Highlights |
|----------|-----------|
| **Auto-Detection** | **Automatically identifies 43+ formats** |
| **Supported Formats** | 43+ handlers: SSH keys, raw hashes (MD5 · SHA-1/256/512), network (NTLM · WPA · Kerberos), documents (PDF · ODF · Office), archives (ZIP · RAR · 7z), KDFs (bcrypt · Argon2 · scrypt), tokens (JWT · Ansible Vault), KeePass `.kdbx`, databases (MySQL · MSSQL · PostgreSQL) |
| **Attacks** | 11 modes Wordlist · Mask · Combinator · PRINCE · Markov · Hybrid · Policy · OSINT · PCFG · AI · Auto-Pwn |
| **Rules** | Hashcat-compatible rule engine 25+ opcodes, built-in rulesets (best64, dive, toggles, unix) |
| **GPU** | CUDA (NVIDIA) + OpenCL (AMD/Intel) auto-detected, zero config |
| **Distributed** | ZeroMQ master/worker architecture linear N-machine scaling |
| **AI** | GPT-2 candidate generation + Markov chain fallback + Spiking Neural Engine **> 🔬 **Proof of Concept** demonstrates the approach, not optimised for production use.** |
| **OSINT** | spaCy NLP profiler builds personal dictionaries from target text **> 🔬 **Proof of Concept** demonstrates the approach, not optimised for production use.** |
| **Sessions** | Auto-save every 30s, safe Ctrl+C, restore across restarts |
| **Results** | SQLite database auto-logs every crack, CSV/JSON export |
| **API** | FastAPI REST server + Rich TUI dashboard |
| **Research** | Quantum bridge (Qiskit) · PQC scanner · Web3/ZK auditor · FPGA acceleration **> ⚠️ **Experimental** functional but not production-hardened. Use with caution.** |

---

## ⚙️ Installation

> **Prerequisites:** See [docs/MANUAL.md → Installation](docs/MANUAL.md#installation) for full system dependency setup (Rust toolchain, CUDA drivers, Docker, etc. Covering all 43 formats, 11 attack modes, GPU setup, distributed cracking, AI/OSINT engine, benchmarks, and more.)

### 🛠️ From Source
```bash
git clone https://github.com/BhanuGuragain0/HashAxe.git
cd HashAxe
```

---

## Screenshots

👉 [View all screenshots](images/)

---

## 🚀 Usage Examples

### 🔍 Identify & Benchmark
```bash
# Identify hash type and show encryption details
python3 -m hashaxe --hash a8dd1a70bd4598e612bb25a000367da5 --info
python3 -m hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' --info
python3 -m hashaxe --hash "a8dd1a70bd4598e612bb25a000367da5" --info
python3 -m hashaxe -k test_files/test_key.ppk --info

# Benchmark speed against a target format
python3 -m hashaxe -k test_files/md5hash.txt --benchmark
```

### 📖 Wordlist Attacks
```bash
# Crack an inline MD5 hash
python3 -m hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' -w test_files/password.txt

# Crack a hash file
python3 -m hashaxe -k test_files/md5hash.txt -w test_files/password.txt

# Crack a PuTTY PPK key
python3 -m hashaxe -k test_files/test_key.ppk -w test_files/password.txt

# OpenSSH key with built-in mutation rules
python3 -m hashaxe -k id_rsa -w passwords.txt --rules
```

### 🎭 Mask Attacks
```bash
# Full mask uppercase + lowercase + special + digits
python3 -m hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' --mask '?u?l?l?l?s?d?d?d?d'

# Known prefix + unknown suffix
python3 -m hashaxe -k server_key.ppk --mask 'Shadow@HTB?d?d?d?d'

# Hybrid: each wordlist entry + 3-digit suffix
python3 -m hashaxe -k id_ed25519 -w rockyou.txt --mask '?d?d?d'
```

### 📏 Rule-Based Attacks
```bash
# Built-in rules (~100 mutations per word)
python3 -m hashaxe -k test_files/test_key.ppk -w test_files/password.txt --rules

# External Hashcat rule file
python3 -m hashaxe -k test_files/test_key.ppk -w test_files/password.txt \
    --rule-file /usr/share/hashcat/rules/best64.rule
```

### 🤖 AI & OSINT
```bash
# AI-powered candidate generation
python3 -m hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' -w test_files/password.txt --ai

# OSINT personal dictionary from target's text
python3 -m hashaxe -k id_rsa --osint-file target_profile.txt -w rockyou.txt
```

### ⚡ Advanced Modes
```bash
# Auto-Pwn fully autonomous pipeline
python3 -m hashaxe -k id_rsa --auto-pwn -w rockyou.txt

# Combinator Cartesian product of two wordlists
python3 -m hashaxe -k id_rsa --attack combinator -w wordlist1.txt --wordlist2 wordlist2.txt

# PRINCE probability-ordered element chaining
python3 -m hashaxe -k id_rsa --attack prince -w rockyou.txt --prince-min 2 --prince-max 4

# PCFG grammar-based generation
python3 -m hashaxe --hash '<hash>' --attack pcfg -w rockyou.txt

# Policy constrained generation
python3 -m hashaxe -k id_rsa --attack policy -w rockyou.txt \
    --policy 'min=8,upper=1,digit=1,special=1'
```

### 💾 Session Management
```bash
# Named session auto-saves every 30s
python3 -m hashaxe -k key -w rockyou.txt --rules --session engagement_htb

# Resume an interrupted session
python3 -m hashaxe -k key -w rockyou.txt --rules --session engagement_htb --restore

# List and delete sessions
python3 -m hashaxe --list-sessions
python3 -m hashaxe --delete-session engagement_htb
```

### 📊 Results & Export
```bash
# View all cracked entries
python3 -m hashaxe --show-results

# Aggregate statistics
python3 -m hashaxe --stats

# Export to CSV or JSON
python3 -m hashaxe --export-results results.csv
python3 -m hashaxe --export-results results.json
```

### 🌐 Distributed & Infrastructure
```bash
# GPU info
python3 -m hashaxe --gpu-info

# Distributed master node
python3 -m hashaxe -k key -w rockyou.txt --distributed-master

# Distributed worker node
python3 -m hashaxe --distributed-worker --master 192.168.1.10

# REST API server
python3 -m hashaxe --api-server --api-port 9090

# TUI real-time dashboard
python3 -m hashaxe -k id_rsa -w rockyou.txt --tui
```

---

## 🖥️ CLI Quick Reference

> **Input:** Use `-k <HASH FILE>` for encrypted files (SSH keys, ZIPs, PDFs, etc.) or `--hash <HASH STRING>` for inline hash strings (MD5, SHA, bcrypt, shadow lines, etc.).

### 📌 All Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-k`, `--key <HASH FILE>` | Path to encrypted file (SSH key, ZIP, PDF, or any supported format) | `python3 -m hashaxe -k id_rsa` |
| `--hash <HASH STRING>` | Inline hash string to crack (MD5, SHA-256, bcrypt, shadow line, etc.) | `python3 -m hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5'` |
| `--info` | Display file/hash metadata and exit no cracking | `python3 -m hashaxe --hash 'a8dd1...' --info` or `python3 -m hashaxe -k file.ppk --info` |
| `--format FMT` | Force specific format overrides auto-detection | `--format hash.md5` or `--format ssh.ppk` `python3 -m hashaxe --format hash.md5 -k test_files/md5hash.txt -w test_files/password.txt` |

### ⚔️ Attack Configuration

| Flag | Description | Example |
|------|-------------|---------|
| `--attack MODE` | Attack mode | `wordlist` `mask` `combinator` `prince` `markov` `hybrid` `policy` `osint` `pcfg` |
| `-w`, `--wordlist FILE` | Path to wordlist (use `-` for stdin). Not needed for mask-only attacks | `-w /usr/share/wordlists/rockyou.txt` |
| `--wordlist2 FILE` | Second wordlist for combinator attack | `--wordlist2 suffixes.txt` |
| `--mask MASK` | Hashcat-style mask | `?l`=lower `?u`=upper `?d`=digit `?s`=special `?a`=all |
| `-1`/`-2`/`-3`/`-4` CS | Custom charsets for `?1`–`?4` mask tokens | `-1 'abc123'` |
| `--rules` | Apply built-in mutation rules (~100 variants per word) | `--rules` |
| `--rule-file FILE` | Path to Hashcat `.rule` file | `--rule-file best64.rule` |
| `--policy RULES` | Password policy constraints | `--policy 'min=8,upper=1,digit=1,special=1'` |
| `--markov-order N` | Markov chain order, 1–6 (default: 3) | `--markov-order 4` |
| `--prince-min N` / `--prince-max N` | PRINCE element chain range (default: 1–4) | `--prince-min 2 --prince-max 5` |
| `--auto-pwn` | Run intelligent Auto-Pwn orchestration pipeline | `--auto-pwn` |

### 🤖 AI & OSINT

| Flag | Description | Example |
|------|-------------|---------|
| `--ai` | Enable AI-powered candidate generation (GPT-2 + Markov fallback) | `--ai` |
| `--candidates N` | Number of AI-generated candidates per seed (default: 1000) | `--candidates 5000` |
| `--download-models` | Download and cache AI models (GPT-2) for offline use | `--download-models` |
| `--osint-file FILE` | OSINT source file (tweets, bio, social media dump) | `--osint-file target_bio.txt` |
| `--osint-export FILE` | Export OSINT-generated wordlist to file without cracking | `--osint-export wordlist.txt` |

### ⚡ Performance

| Flag | Description | Example |
|------|-------------|---------|
| `-t`, `--threads N` | Parallel worker processes (default: auto = all CPUs) | `-t 8` |
| `--gpu` | Enable GPU acceleration (default behavior) | `--gpu` |
| `--no-gpu` | Disable GPU force CPU-only multiprocessing | `--no-gpu` |
| `--gpu-info` | Display detected GPU info and exit | `--gpu-info` |
| `--no-smart-order` | Disable frequency-based candidate reordering | `--no-smart-order` |
| `--benchmark` | Benchmark passphrase testing speed and exit | `--benchmark` |
| `--estimate WORDS` | Estimate crack time for N wordlist entries and exit | `--estimate 14000000` |

### 🌐 Distributed Cracking

| Flag | Description | Example |
|------|-------------|---------|
| `--distributed-master` | Run as distributed master node | `--distributed-master` |
| `--distributed-worker` | Run as distributed worker node | `--distributed-worker` |
| `--master HOST` | Master node hostname/IP (for `--distributed-worker`) | `--master 192.168.1.10` |
| `--work-port PORT` | ZMQ work dispatch port (default: 5555) | `--work-port 5555` |
| `--result-port PORT` | ZMQ result collection port (default: 5556) | `--result-port 5556` |

### 💾 Session Management

| Flag | Description | Example |
|------|-------------|---------|
| `--restore` | Resume a previously interrupted session | `--restore` |
| `--session NAME` | Named session (overrides auto-generated name) | `--session htb_target` |
| `--list-sessions` | List all saved sessions and exit | `--list-sessions` |
| `--delete-session NAME` | Delete a named session and exit | `--delete-session htb_target` |

### 🔍 SSH Verification

| Flag | Description | Example |
|------|-------------|---------|
| `--verify-host HOST` | SSH host to test the cracked passphrase against | `--verify-host 10.10.11.5` |
| `--verify-port PORT` | SSH port (default: 22) | `--verify-port 2222` |
| `--verify-user USER` | SSH username for live verification | `--verify-user root` |

### 📊 Output & Results

| Flag | Description | Example |
|------|-------------|---------|
| `-o`, `--output FILE` | Save cracked passphrase to file | `-o cracked.txt` |
| `-v`, `--verbose` | Verbose output per-worker stats instead of progress bar | `-v` |
| `-q`, `--quiet` | Suppress all output except the passphrase itself | `-q` |
| `--tui` | Use advanced real-time Terminal UI dashboard | `--tui` |
| `--show-results` | Display all cracked entries from the database | `--show-results` |
| `--stats` | Show aggregate cracking statistics | `--stats` |
| `--export-results FILE` | Export results to `.csv` or `.json` | `--export-results out.json` |
| `--filter-format FMT` | Filter results by format ID | `--filter-format hash.md5` |
| `--clear-results` | Delete all saved results (**destructive**) | `--clear-results` |

### 🔌 API Server

| Flag | Description | Example |
|------|-------------|---------|
| `--api-server` | Launch headless REST API server for C2 integration | `--api-server` |
| `--api-port PORT` | Port for the API server (default: 8080) | `--api-port 9090` |

---

## 🗂️ Supported Formats (43+)

| Category | Formats |
|----------|---------|
| **🔑 SSH Keys** | OpenSSH (Ed25519 · RSA · ECDSA · DSA), PuTTY PPK v2/v3 |
| **#️⃣ Raw Hashes** | MD5, SHA-1, SHA-256, SHA-512, NTLM, LM |
| **🔐 KDFs** | bcrypt, Argon2id/i/d, scrypt, PBKDF2 |
| **🐧 Unix Crypt** | md5crypt, sha256crypt, sha512crypt, DES crypt |
| **🌐 Network** | NetNTLMv1/v2, WPA/WPA2, Kerberos TGS/AS-REP, DCC v1/v2, Cisco Type 5/8/9 |
| **🗄️ Databases** | MySQL, PostgreSQL, MSSQL, Oracle |
| **📦 Archives** | ZIP (ZipCrypto + AES-256), 7-Zip, RAR |
| **📄 Documents** | PDF (RC4/AES), Office (Word · Excel · PowerPoint), ODF |
| **🪙 Tokens** | JWT (HS256 · HS384 · HS512), Ansible Vault |
| **💽 Disk / OS** | DPAPI Masterkeys, macOS Keychain |
| **🔒 Password Managers** | KeePass, 1Password, LastPass, Bitwarden |
| **🔣 Encoding** | Base64-wrapped hashes |

> 📖 See [docs/MANUAL.md → Supported Formats](docs/MANUAL.md#supported-formats-43) for complete per-format specification cards including GPU compatibility, Hashcat mode mappings, and input methods.

---

## ⚡ Performance

> 📖 See [docs/MANUAL.md → Performance Benchmarks](docs/MANUAL.md#performance-benchmarks) for full hardware matrix and KDF rounds impact.

---

## 🤝 Contributing

Contributions are welcome from the community.

- 🐛 **Bug reports** → [GitHub Issues](https://github.com/GANGA-Offensive-Ops/HashAxe/issues)
- 💡 **Feature requests** → [GitHub Issues](https://github.com/GANGA-Offensive-Ops/HashAxe/issues)
- 🔧 **Pull requests** → [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, code style, and PR guidelines

---

## ⚠️ Responsible Use

> **This tool is strictly for authorised penetration testing, CTF competitions, and security research.**
> Always obtain **written permission** before testing any system you do not own or have explicit authorisation to assess.
> Unauthorised use against systems you do not own is **illegal** in most jurisdictions.

- 📜 Usage is governed by the [Apache 2.0 License](LICENSE)
- 🇳🇵 Developed responsibly under **GANGA Offensive Ops**, Nepal

---
## 📄 License

HashAxe is licensed under the **Apache License 2.0** see the LICENSE [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)

> You are free to use, modify, and distribute this software. Any patent rights from contributors are explicitly granted to users. If you initiate patent litigation against this project, your license terminates automatically.

---

<p align="center">
  <b>Developed under GANGA Offensive Ops</b>
</p>

<p align="center">
  <a href="https://github.com/BhanuGuragain0">
    <img src="https://img.shields.io/badge/Bhanu%20Guragain-BhanuGuragain0-red?style=flat-square&logo=github"/>
  </a>
  &nbsp;
  <a href="https://github.com/Shr1H4x">
    <img src="https://img.shields.io/badge/Shrijesh%20Pokharel-Shr1H4x-blue?style=flat-square&logo=github"/>
  </a>
  &nbsp;
  <a href="https://github.com/rumjoe">
    <img src="https://img.shields.io/badge/Aashish%20Panthi-rumjoe-green?style=flat-square&logo=github"/>
  </a>
</p>
