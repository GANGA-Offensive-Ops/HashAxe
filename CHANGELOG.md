# Changelog — Crack

All notable changes to this project are documented here.
Format: [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2026-03-12

### Added

**OSINT Intelligence Layer**

- `hashaxe/osint/profiler.py` — Target profile builder from unstructured text
- `hashaxe/osint/keyword_mutator.py` — Personal keyword expansion engine
- `hashaxe/osint/nlp_engine.py` — spaCy NLP entity extraction
- `hashaxe/attacks/osint.py` — OSINT attack plugin
- `--osint-file`, `--osint-export` CLI flags

**Advanced Machine Learning**

- `hashaxe/attacks/pcfg.py` — Probabilistic Context-Free Grammar generator
- `hashaxe/ai/adaptive.py` — RL-inspired adaptive temperature controller
- `hashaxe/ai/spiking_engine.py` — Neuromorphic SNN temporal pattern engine
- `--attack pcfg` CLI mode

**Auto-Pwn + API + TUI**

- `hashaxe/auto_pwn.py` — Autonomous multi-phase attack orchestrator
- `hashaxe/api.py` — FastAPI REST server for remote C2 integration
- `hashaxe/tui/app.py` — Rich-powered interactive TUI dashboard
- `--auto-pwn`, `--api-server`, `--api-port`, `--tui` CLI flags

**Performance Monitor**

- `hashaxe/monitor.py` — Real-time speed, ETA, GPU/CPU utilization tracker

**Distributed Fault Tolerance**

- `hashaxe/distributed/healing.py` — Heartbeat monitoring, dead worker detection, job re-queuing
- `hashaxe/distributed/ipfs_node.py` — IPFS/BitTorrent wordlist syncing

**Quantum Computing Bridge**

- `hashaxe/quantum/qiskit_bridge.py` — Qiskit-Aer GPU simulator integration
- `hashaxe/quantum/grover_oracle.py` — Grover's Algorithm search oracle POC

**Post-Quantum Cryptography Scanner**

- `hashaxe/pqc/scanner.py` — NIST ML-KEM vulnerability scanner
- `hashaxe/pqc/hndl_analyzer.py` — Harvest-Now-Decrypt-Later lifecycle analyzer

**FPGA Assimilation**

- `hashaxe/fpga/bridge.py` — PCIe interface module + simulation mode

**Web3 & Zero-Knowledge**

- `hashaxe/web3/zk_auditor.py` — Ethereum v3 keystore + BIP39 mnemonic analysis

**CLI Enhancements**

- `--candidates N` flag for controlling AI generation count
- `--attack MODE` flag unified for all 11 attack modes
- Early validation with clear error messages for PCFG, AI, Combinator, Distributed modes

**Tests** (578 total, up from 163)

- `tests/test_osint.py` — 42 tests (profiler, NLP, keyword mutations)
- `tests/test_pcfg_ai.py` — 29 tests (PCFG grammar, AI generator, adaptive temp)
- `tests/test_auto_pwn_api_tui.py` — 27 tests (pipeline, REST API, TUI)
- `tests/test_monitor_healing.py` — 27 tests (performance monitor, fault tolerance)
- `tests/test_v4_advanced.py` — 95 tests (quantum, PQC, SNN, FPGA, Web3/ZK)

### Changed

- `hashaxe/__init__.py` — version bumped to 1.0.0
- `hashaxe/cli.py` — 15+ new arguments, improved validation logic
- `hashaxe/cracker.py` — `ai_candidates` parameter flow
- `hashaxe/attacks/__init__.py` — `ai_candidates` field in `AttackConfig`

---

## [3.0.0] — 2026-03-10

### Added (V3 — Formats, Attacks, Database)

**Format Plugin Architecture**

- `hashaxe/formats/` package — `BaseFormat` ABC + `FormatRegistry` auto-discovery
- `hashaxe/formats/ssh_openssh.py` — OpenSSH new + legacy PEM handler
- `hashaxe/formats/ssh_ppk.py` — PuTTY PPK v2/v3 handler
- `hashaxe/formats/hash_raw.py` — MD5, SHA-1/256/512, NTLM
- `hashaxe/formats/hash_unix.py` — md5crypt, sha256crypt, sha512crypt
- `hashaxe/formats/hash_bcrypt.py` — bcrypt ($2a$/$2b$)
- `hashaxe/formats/hash_argon2.py` — Argon2id/i/d
- `hashaxe/formats/hash_scrypt.py` — scrypt
- `hashaxe/formats/archive_zip.py` — ZIP (ZipCrypto + AES)
- `hashaxe/formats/archive_7z.py` — 7-Zip (AES-256)
- `hashaxe/formats/document_pdf.py` — PDF (RC4-40/128, AES-128/256)
- `hashaxe/formats/database_mysql.py` — MySQL double-SHA1
- `hashaxe/formats/database_postgres.py` — PostgreSQL MD5+user
- `hashaxe/formats/database_mssql.py` — MSSQL SHA-512 salted
- `hashaxe/formats/token_jwt.py` — JWT HMAC-SHA256/384/512
- `hashaxe/formats/network_ntlm.py` — NetNTLMv1/v2
- `hashaxe/formats/network_wpa.py` — WPA/WPA2 PBKDF2

**Auto-Identification Engine**

- `hashaxe/identify/magic.py` — File magic bytes detection
- `hashaxe/identify/hash_patterns.py` — 50+ regex patterns for hash strings
- `hashaxe/identify/entropy.py` — Shannon entropy fallback classifier
- `--hash`, `--format` CLI flags + auto-detect default

**Attack Mode Plugins**

- `hashaxe/attacks/__init__.py` — `BaseAttack` ABC + `AttackRegistry`
- `hashaxe/attacks/wordlist.py` — Streaming wordlist with length filtering
- `hashaxe/attacks/mask.py` — ?l/?u/?d/?s/?a + custom charsets
- `hashaxe/attacks/combinator.py` — Cartesian product of two wordlists
- `hashaxe/attacks/prince.py` — PRINCE probability-ordered chaining
- `hashaxe/attacks/markov.py` — Markov chain generation (configurable order)
- `hashaxe/attacks/hybrid.py` — Wordlist + mask suffix
- `hashaxe/attacks/policy.py` — Policy-constrained generation/filtering
- `hashaxe/attacks/ai_generator.py` — GPT-2 / Markov fallback generator
- `--attack MODE`, `--wordlist2`, `--policy`, `--markov-order`, `--prince-min/max` CLI flags

**Results Database**

- `hashaxe/db/schema.py` — SQLite schema + migrations
- `hashaxe/db/manager.py` — CrackDB CRUD operations
- `hashaxe/db/export.py` — CSV/JSON export
- `--show-results`, `--stats`, `--export-results`, `--filter-format`, `--clear-results` CLI flags
- Auto-log on every successful hashaxe

**AI Integration**

- `hashaxe/ai/model_manager.py` — HuggingFace model download/cache
- `--ai`, `--download-models` CLI flags
- Markov fallback when no torch installed

**GPU Kernels**

- `hashaxe/gpu/kernels/md5.cu` — Dedicated MD5 CUDA kernel
- `hashaxe/gpu/kernels/sha256.cu` — Dedicated SHA-256 CUDA kernel
- `hashaxe/gpu/kernels/ntlm.cu` — Dedicated NTLM CUDA kernel

**Tests** (415 new since V2, 578 cumulative)

- `tests/test_formats.py` — 35 tests
- `tests/test_identify.py` — 29 tests
- `tests/test_db.py` — 25 tests
- `tests/test_archives.py` — 41 tests
- `tests/test_network_db.py` — 39 tests
- `tests/test_attacks.py` — 26 tests

### Changed

- `hashaxe/cracker.py` — FormatRegistry integration for all 30+ formats
- `hashaxe/cli.py` — 20+ new arguments for formats, attacks, database

---

## [2.0.0] — 2026-03-09

### Added (V2 — GPU + Distributed)

**GPU Acceleration**

- `hashaxe/gpu/accelerator.py` — Auto-detect CUDA (NVIDIA) or OpenCL (any GPU)
- `hashaxe/gpu/cuda_kernel.cu` — NVIDIA CUDA bcrypt kernel (sm_86/sm_89)
- `hashaxe/gpu/opencl_kernel.cl` — OpenCL bcrypt kernel (cross-vendor)
- `--gpu-info`, `--no-gpu` CLI flags

**CPU SIMD Batching**

- `hashaxe/cpu/simd.py` — NumPy vectorised AES + ctypes AES-NI
- `hashaxe/cpu/wordfreq.py` — Breach-frequency smart ordering
- `--no-smart-order` CLI flag

**Distributed Cracking**

- `hashaxe/distributed/master.py` — ZeroMQ PUSH/PULL/PUB master node
- `hashaxe/distributed/worker.py` — Worker node with GPU/CPU auto-routing
- `--distributed-master`, `--distributed-worker`, `--master`, `--work-port`, `--result-port`
- `docker-compose.yml` for multi-container scaling

**Cloud Deployment**

- `scripts/deploy_aws.py` — AWS G5 spot instance auto-deploy

**Infrastructure**

- `.github/workflows/ci.yml` — 6-job CI pipeline
- `.github/workflows/release.yml` — Sigstore-signed PyPI release
- `.github/workflows/codeql.yml` — Weekly security scan
- `.pre-commit-config.yaml` — ruff · black · isort · mypy · bandit
- `Dockerfile` — Multi-stage GPU/CPU build

**Documentation**

- `docs/GPU_SETUP.md`, `docs/DISTRIBUTED.md`, `docs/BENCHMARKS.md`, `docs/COVERAGE.md`

**Tests** (62 new, 163 total)

- `tests/test_batch2.py` — 62 tests across 7 classes

---

## [1.0.0] — 2026-03-08

### Added (V1 — Core Engine)

**Core engine**

- `hashaxe/parser.py` — OpenSSH new format, legacy PEM, PPK v2/v3
- `hashaxe/engine.py` — fast-path checkints + full key-load confirmation
- `hashaxe/cracker.py` — multiprocessing orchestrator
- `hashaxe/wordlist.py` — streaming byte-range chunker (OOM-safe)
- `hashaxe/session.py` — save/resume sessions
- `hashaxe/display.py` — progress bar, result boxes, benchmark output
- `hashaxe/cli.py` — CLI entry point

**Attack modes**

- Wordlist (streaming, O(1) memory per worker)
- Built-in mutation rules (~100 mutations per word)
- Hashcat .rule file support (25+ opcodes, Best64 built-in)
- Mask attack (?l?u?d?s?a?b + custom charsets)
- Hybrid (wordlist × mask)

**Key format support**

- OpenSSH new: Ed25519, RSA, ECDSA, DSA (bcrypt KDF)
- OpenSSH legacy PEM: RSA, ECDSA, DSA
- PuTTY PPK v2 (HMAC-SHA1 + AES-256-CBC + MD5 KDF)
- PuTTY PPK v3 (HMAC-SHA256 + AES-256-CBC + Argon2id KDF)

**Tests** (101)

- `tests/test_all.py` — 101 tests across 9 classes
