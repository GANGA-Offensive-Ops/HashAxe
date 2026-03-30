<p align="center">
  <img src="images/HashAxe_Banner.png" alt="HashAxe Banner" width="700"/>
</p>

<h1 align="center">HashAxe V1 — Advanced Password Cracker</h1>

<p align="center">
  <b>Multi-Format Password Recovery Tool for Pentesters, Red Teams & CTFs</b><br/>
  <em>43+ Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI/JWT & more</em><br/>
  <em>GPU-Accelerated · Distributed · AI-Powered · Auto-Pwn</em>
</p>

<p align="center">
  <a href="https://github.com/GANGAOps/HashAxe/actions"><img src="https://img.shields.io/github/actions/workflow/status/GANGA-Offensive-Ops/Hashaxe/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="docs/MANUAL.md#test-suite--coverage"><img src="https://img.shields.io/badge/tests-578%20passing-brightgreen" alt="Tests"></a>
  <a href="docs/MANUAL.md#test-suite--coverage"><img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Coverage"></a>
  <a href="docs/MANUAL.md#gpu-acceleration"><img src="https://img.shields.io/badge/GPU-CUDA%20%7C%20OpenCL-76b900" alt="GPU"></a>
  <a href="docs/MANUAL.md#distributed-cracking"><img src="https://img.shields.io/badge/distributed-ZeroMQ-orange" alt="Distributed"></a>
  <a href="https://pypi.org/project/hashaxe/"><img src="https://img.shields.io/badge/PyPI-hashaxe-blue" alt="PyPI"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.8%20→%203.13-blue" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
  <a href="https://github.com/GANGAOps/HashAxe/releases"><img src="https://img.shields.io/badge/release-v1.0.0_stable-blue.svg" alt="Release"></a>
</p>

---

> **⚡ Project Status:** Core features — wordlist attacks, mask attacks, verbose mode, info commands, rules, and session management — are fully tested and production-ready on Kali Linux baremetal. AI and OSINT engines ship as simplified implementations; full integration with our autonomous offensive system is planned for v2. This tool is built for CTF players, pentesting students, and security professionals.

📖 **[Read the Complete Reference Manual →](docs/MANUAL.md)** — 2000+ lines covering all 43 formats, 11 attack modes, GPU setup, distributed cracking, AI/OSINT engine, benchmarks, and more.

---

## Features

| Category | Highlights |
|----------|-----------|
| **Formats** | 43+ handlers — SSH keys, raw hashes, KDFs, archives, documents, databases, network protocols, tokens |
| **Attacks** | 11 modes — Wordlist · Mask · Combinator · PRINCE · Markov · Hybrid · Policy · OSINT · PCFG · AI · Auto-Pwn |
| **Rules** | Hashcat-compatible rule engine — 25+ opcodes, built-in rulesets (best64, dive, toggles, unix) |
| **GPU** | CUDA (NVIDIA) + OpenCL (AMD/Intel) — auto-detected, zero config |
| **Distributed** | ZeroMQ master/worker architecture — linear N-machine scaling |
| **AI** | GPT-2 candidate generation + Markov chain fallback + Spiking Neural Engine |
| **OSINT** | spaCy NLP profiler — builds personal dictionaries from target text |
| **Sessions** | Auto-save every 30s, safe Ctrl+C, restore across restarts |
| **Results** | SQLite database — auto-logs every crack, CSV/JSON export |
| **API** | FastAPI REST server + Rich TUI dashboard |
| **Research** | Quantum bridge (Qiskit) · PQC scanner · Web3/ZK auditor · FPGA acceleration |

---

## Installation

```bash
# Core (CPU only)
pip install hashaxe

# With GPU support (NVIDIA CUDA)
pip install "hashaxe[gpu-cuda]"

# With PPK v3 / Argon2id support
pip install "hashaxe[ppk-v3]"

# With distributed cracking
pip install "hashaxe[distributed]"

# Everything
pip install "hashaxe[all]"

# Development setup
pip install -e ".[dev]"
```

> See [docs/MANUAL.md — Installation](docs/MANUAL.md#installation) for full system dependency setup (Rust toolchain, CUDA drivers, Docker, etc.).

---

## CLI Quick Reference

> **Input:** Use `-k FILE` for encrypted files (SSH keys, ZIPs, PDFs, etc.) or `--hash STRING` for inline hash strings (MD5, SHA, bcrypt, shadow lines, etc.).

### All Flags

| Flag | Description |
|------|-------------|
| `-k`, `--key FILE` | Path to encrypted file (SSH key, ZIP, PDF, or any supported format) |
| `--hash HASH` | Inline hash string to crack (MD5, SHA-256, bcrypt, shadow line, etc.) |
| `--format FMT` | Force specific format — overrides auto-detection (e.g., `hash.md5`, `ssh.ppk`) |
| `-w`, `--wordlist FILE` | Path to wordlist (use `-` for stdin). Not needed for mask-only attacks |
| `-t`, `--threads N` | Parallel worker processes (default: auto = all CPUs) |
| `--rules` | Apply built-in mutation rules (~100 variants per word) |
| `--rule-file FILE` | Path to Hashcat `.rule` file (e.g., `best64.rule`, `OneRuleToRuleThemAll.rule`) |
| `--mask MASK` | Hashcat-style mask — `?l`=lower `?u`=upper `?d`=digit `?s`=special `?a`=all |
| `-1`/`-2`/`-3`/`-4` CS | Custom charsets for `?1`–`?4` mask tokens |
| `--attack MODE` | Attack mode: `wordlist` `mask` `combinator` `prince` `markov` `hybrid` `policy` `osint` `pcfg` |
| `--auto-pwn` | Run intelligent Auto-Pwn orchestration pipeline |
| `--wordlist2 FILE` | Second wordlist for combinator attack |
| `--policy RULES` | Password policy constraints (e.g., `min=8,upper=1,digit=1,special=1`) |
| `--markov-order N` | Markov chain order, 1–6 (default: 3) |
| `--prince-min N` / `--prince-max N` | PRINCE element chain range (default: 1–4) |
| `--ai` | Enable AI-powered candidate generation (GPT-2 + Markov fallback) |
| `--candidates N` | Number of AI-generated candidates per seed (default: 1000) |
| `--download-models` | Download and cache AI models (GPT-2) for offline use |
| `--osint-file FILE` | OSINT source file (tweets, bio, social media dump) |
| `--osint-export FILE` | Export OSINT-generated wordlist to file without cracking |
| `-o`, `--output FILE` | Save cracked passphrase to file |
| `-v`, `--verbose` | Verbose output — per-worker stats instead of progress bar |
| `-q`, `--quiet` | Suppress all output except the passphrase itself |
| `--tui` | Use advanced real-time Terminal UI dashboard |
| `--restore` | Resume a previously interrupted session |
| `--session NAME` | Named session (overrides auto-generated name) |
| `--list-sessions` | List all saved sessions and exit |
| `--delete-session NAME` | Delete a named session and exit |
| `--verify-host HOST` | SSH host to test the cracked passphrase against |
| `--verify-port PORT` | SSH port (default: 22) |
| `--verify-user USER` | SSH username for live verification |
| `--info` | Display file/hash metadata and exit (no cracking) |
| `--benchmark` | Benchmark passphrase testing speed and exit |
| `--estimate WORDS` | Estimate crack time for N wordlist entries and exit |
| `--api-server` | Launch headless REST API server for C2 integration |
| `--api-port PORT` | Port for the API server (default: 8080) |
| `--gpu` | Enable GPU acceleration (default behavior) |
| `--no-gpu` | Disable GPU — force CPU-only multiprocessing |
| `--gpu-info` | Display detected GPU info and exit |
| `--distributed-master` | Run as distributed master node |
| `--distributed-worker` | Run as distributed worker node |
| `--master HOST` | Master node hostname/IP (for `--distributed-worker`) |
| `--work-port PORT` | ZMQ work dispatch port (default: 5555) |
| `--result-port PORT` | ZMQ result collection port (default: 5556) |
| `--no-smart-order` | Disable frequency-based candidate reordering |
| `--show-results` | Display all cracked entries from the database |
| `--stats` | Show aggregate cracking statistics |
| `--export-results FILE` | Export results to `.csv` or `.json` |
| `--filter-format FMT` | Filter results by format ID |
| `--clear-results` | Delete all saved results (**destructive**) |

---

## Usage Examples

### Identify & Benchmark

```bash
# Identify hash type and show encryption details
hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' --info
hashaxe -k test_files/test_key.ppk --info

# Benchmark speed against a target format
hashaxe -k test_files/md5hash.txt --benchmark
```

### Wordlist Attacks

```bash
# Crack an inline MD5 hash
hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' -w test_files/password.txt

# Crack a hash file
hashaxe -k test_files/md5hash.txt -w test_files/password.txt

# Crack a PuTTY PPK key
hashaxe -k test_files/test_key.ppk -w test_files/password.txt

# OpenSSH key with built-in mutation rules
hashaxe -k id_rsa -w passwords.txt --rules
```

### Mask Attacks

```bash
# Full mask — uppercase + lowercase + special + digits
hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' --mask '?u?l?l?l?s?d?d?d?d'

# Known prefix + unknown suffix
hashaxe -k server_key.ppk --mask 'Shadow@HTB?d?d?d?d'

# Hybrid: each wordlist entry + 3-digit suffix
hashaxe -k id_ed25519 -w rockyou.txt --mask '?d?d?d'
```

### Rule-Based Attacks

```bash
# Built-in rules (~100 mutations per word)
hashaxe -k test_files/test_key.ppk -w test_files/password.txt --rules

# External Hashcat rule file
hashaxe -k test_files/test_key.ppk -w test_files/password.txt \
    --rule-file /usr/share/hashcat/rules/best64.rule
```

### AI & OSINT

```bash
# AI-powered candidate generation
hashaxe --hash 'a8dd1a70bd4598e612bb25a000367da5' -w test_files/password.txt --ai

# OSINT — personal dictionary from target's text
hashaxe -k id_rsa --osint-file target_profile.txt -w rockyou.txt
```

### Advanced Modes

```bash
# Auto-Pwn — fully autonomous pipeline
hashaxe -k id_rsa --auto-pwn -w rockyou.txt

# Combinator — Cartesian product of two wordlists
hashaxe -k id_rsa --attack combinator -w wordlist1.txt --wordlist2 wordlist2.txt

# PRINCE — probability-ordered element chaining
hashaxe -k id_rsa --attack prince -w rockyou.txt --prince-min 2 --prince-max 4

# PCFG — grammar-based generation
hashaxe --hash '<hash>' --attack pcfg -w rockyou.txt

# Policy — constrained generation
hashaxe -k id_rsa --attack policy -w rockyou.txt --policy 'min=8,upper=1,digit=1,special=1'
```

### Session, Results & Infrastructure

```bash
# Named session (auto-saves every 30s)
hashaxe -k key -w rockyou.txt --rules --session engagement_htb

# Resume a session
hashaxe -k key -w rockyou.txt --rules --session engagement_htb --restore

# Manage sessions
hashaxe --list-sessions
hashaxe --delete-session engagement_htb

# View & export cracked results
hashaxe --show-results
hashaxe --stats
hashaxe --export-results results.csv

# GPU info
hashaxe --gpu-info

# Distributed master/worker
hashaxe -k key -w rockyou.txt --distributed-master
hashaxe --distributed-worker --master 192.168.1.10

# REST API server
hashaxe --api-server --api-port 9090

# TUI dashboard
hashaxe -k id_rsa -w rockyou.txt --tui
```

---

## Screenshots

<p align="center">
  <img src="images/wordlist_attack.png" alt="Wordlist Attack" width="700"/><br/>
  <em>Wordlist attack — PPK v3 key cracked in 62s</em>
</p>

<p align="center">
  <img src="images/mask_attack.png" alt="Mask Attack" width="700"/><br/>
  <em>Mask attack — Shadow@HTB?d?d?d?d</em>
</p>

<p align="center">
  <img src="images/openssh_attack.png" alt="OpenSSH Attack" width="700"/><br/>
  <em>OpenSSH bcrypt key with mutation rules</em>
</p>

<p align="center">
  <img src="images/rockyou_attack.png" alt="Rockyou Attack" width="700"/><br/>
  <em>Full rockyou.txt wordlist attack</em>
</p>

---

## Supported Formats (43+)

| Category | Formats |
|----------|---------|
| **SSH Keys** | OpenSSH (Ed25519/RSA/ECDSA/DSA), PuTTY PPK v2/v3 |
| **Raw Hashes** | MD5, SHA-1/256/512, NTLM, LM |
| **KDFs** | bcrypt, Argon2id/i/d, scrypt, PBKDF2 |
| **Unix Crypt** | md5crypt, sha256crypt, sha512crypt, DES crypt |
| **Network** | NetNTLMv1/v2, WPA/WPA2, Kerberos TGS/AS-REP, DCC v1/v2, Cisco Type 5/8/9 |
| **Databases** | MySQL, PostgreSQL, MSSQL, Oracle |
| **Archives** | ZIP (ZipCrypto + AES), 7-Zip, RAR |
| **Documents** | PDF (RC4/AES), Office (Word/Excel/PPT), ODF |
| **Tokens** | JWT (HMAC-SHA256/384/512), Ansible Vault |
| **Disk/OS** | DPAPI masterkeys, macOS Keychain |
| **Password Managers** | KeePass, 1Password, LastPass, Bitwarden |
| **Encoding** | Base64-wrapped hashes |

> See [docs/MANUAL.md — Supported Formats](docs/MANUAL.md#supported-formats-43) for complete per-format specification cards with GPU compatibility, Hashcat modes, and input methods.

---

## Performance

| Format | Hardware | Speed | rockyou.txt (14M) ETA |
|--------|----------|------:|----------------------:|
| PPK v3 (Argon2id) | RTX 3050 + 16-core | 8.3 pw/s | ~19.5 days |
| PPK v3 (Argon2id) | 4× RTX 4090 | ~180 pw/s | ~21.6 hours |
| OpenSSH bcrypt | 16-core CPU | ~75,000 pw/s | ~3 min |
| OpenSSH bcrypt | RTX 4090 | ~200,000 pw/s | ~72 sec |
| Raw MD5 | RTX 3050 | ~50M pw/s | <1 sec |

> See [docs/MANUAL.md — Performance Benchmarks](docs/MANUAL.md#performance-benchmarks) for full hardware matrix and KDF rounds impact.

---

## Docker

```bash
# CPU
docker run --rm -v $(pwd):/work ghcr.io/bh4nu/hashaxe:1.0.0 \
    -k /work/key -w /work/rockyou.txt

# GPU (NVIDIA)
docker run --rm --gpus all -v $(pwd):/work ghcr.io/bh4nu/hashaxe:1.0.0-gpu \
    -k /work/key -w /work/rockyou.txt

# Distributed (Docker Compose)
docker-compose up --scale worker=4
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup and guidelines.

---

## Responsible Use

> **⚠️ This tool is for authorised penetration testing and security research only.**
> Always obtain written permission before testing any system you do not own.

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

---

## License

MIT — see [LICENSE](LICENSE)

---

<p align="center">
  Developed under <b>GANGA Offensive Ops</b><br/>
</p>
