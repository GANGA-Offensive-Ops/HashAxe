# Contributing to hashaxe

Thank you for contributing to the world's fastest open-source SSH key hashaxeer.

---

## Development Setup

```bash
# Clone
git clone https://github.com/GANGAOps/HashAxe
cd hashaxe

# Virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in dev mode with all extras
pip install -e ".[dev,all]"

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type commit-msg
```

---

## Before Every Commit

Pre-commit hooks run automatically. To run manually:

```bash
# All hooks
pre-commit run --all-files

# Individual tools
ruff check hashaxe/ --fix       # lint + auto-fix
black hashaxe/ tests/            # format
isort hashaxe/ tests/            # import order
bandit -r hashaxe/ -ll           # security scan

# Tests
python3 tests/test_all.py
python3 -m unittest tests/test_batch2.py
```

All checks must pass. Zero exceptions.

---

## Commit Message Convention

Uses [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(engine):   add ChaCha20-Poly1305 fast-path for PPK v3
fix(parser):    correct ECDSA CBC block size from 16 to full edata
perf(gpu):      reduce CUDA kernel launch overhead by 40%
test(batch2):   add 6 SIMD integration tests
docs(gpu):      add AMD ROCm setup guide
ci(release):    add Sigstore signing step
security(opsec): pin all dependencies to exact versions
```

Commits to `main` require PRs — direct push is blocked.

---

## Code Style

| Rule | Enforced by |
|------|-------------|
| Line length ≤ 100 | ruff + black |
| Import order | isort (black profile) |
| Type hints required on public APIs | mypy |
| Docstrings on all public functions | interrogate (≥70%) |
| f-strings preferred over % format | ruff UP |
| No bare `except:` | ruff B |

---

## Adding a New Attack Mode

1. Add candidate generator in `hashaxe/rules/` or `hashaxe/cpu/`
2. Expose CLI flag in `hashaxe/cli.py`
3. Wire into `hashaxe/hashaxeer.py` worker dispatch
4. Add tests — minimum 5 unit tests + 2 integration tests
5. Update `docs/BENCHMARKS.md` with speed data
6. Update `CHANGELOG.md` under `[Unreleased]`

---

## Adding Key Format Support

1. Add format detection in `hashaxe/parser.py` `parse_key_file()`
2. Add fast-path in `hashaxe/engine.py` `try_passphrase()`
3. Add full-confirm in `hashaxe/engine.py` `try_passphrase_full()`
4. Add test key fixture in `tests/keys/`
5. Add parser test + engine test + integration test

---

## Performance PRs

For any PR claiming a speed improvement, provide:

```
Benchmark methodology:
  Platform: [CPU/GPU/RAM/OS]
  Key:      [Ed25519/RSA/ECDSA, rounds=N]
  Wordlist: [rockyou.txt or synthetic N-word list]
  Runs:     10 independent, median reported

Before: X pw/s ± σ
After:  Y pw/s ± σ  (+Z%)
```

---

## Security Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.
Do NOT open public issues for security vulnerabilities.
PGP key: available on security.md.
