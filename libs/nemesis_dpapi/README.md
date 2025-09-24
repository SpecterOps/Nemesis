# Tests
Run all unit tests:
```bash
poetry run pytest
```



# Benchmarks
Run only benchmark tests:
```bash
poetry run pytest  --benchmark-only -v
```

Run benchmarks in a file:
```bash
poetry run pytest tests/benchmarks/bench_backupkey_decryption.py::TestMasterkeyDecryptionBenchmarks::test_single_masterkey_decryption --benchmark-only -v
```