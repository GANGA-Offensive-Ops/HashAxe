## Summary

<!-- One sentence: what does this PR do? -->

## Type

- [ ] Bug fix
- [ ] New feature / attack mode
- [ ] Performance improvement
- [ ] Documentation
- [ ] CI/CD / tooling
- [ ] Dependency update

## Changes

<!-- List the key changes made -->

-
-

## Testing

<!-- How was this tested? -->

```bash
# Commands run to validate
python3 tests/test_all.py
python3 -m unittest tests/test_batch2.py
# New tests added in:
```

### Test Results

| Suite | Before | After |
|-------|--------|-------|
| test_all.py | 101/101 | X/Y |
| test_batch2.py | 62/62 | X/Y |

## Performance Impact

<!-- For engine/GPU/SIMD changes: benchmark before/after -->

| Benchmark | Before | After | Delta |
|-----------|--------|-------|-------|
| RSA 16-rounds (1 core) | X pw/s | Y pw/s | ±Z% |

## Checklist

- [ ] All existing tests pass (`python3 tests/test_all.py && python3 -m unittest tests/test_batch2.py`)
- [ ] New tests added for new functionality
- [ ] `ruff check hashaxe/` passes (0 errors)
- [ ] `black --check hashaxe/` passes
- [ ] `bandit -r hashaxe/ -ll` shows 0 CRITICAL / HIGH
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] Docstrings added / updated for public APIs

## Related Issues

Closes #
