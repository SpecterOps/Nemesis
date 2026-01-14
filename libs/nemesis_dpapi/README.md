# Tests
Run all unit tests:
```bash
uv run pytest
```



# Benchmarks
Run only benchmark tests:
```bash
uv run pytest  --benchmark-only -v
```

Run benchmarks in a file:
```bash
uv run pytest tests/benchmarks/bench_backupkey_decryption.py::TestMasterkeyDecryptionBenchmarks::test_single_masterkey_decryption --benchmark-only -v
```