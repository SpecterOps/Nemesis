# File Enrichment Benchmarks

This directory contains performance benchmarks for the file enrichment service.

## Overview

The benchmarks use `pytest-benchmark` to measure the performance of critical functions in the file enrichment pipeline. This helps track performance regressions and identify optimization opportunities.

## Running Benchmarks

### Run all benchmarks

```bash
poetry run pytest tests/benchmarks/ --benchmark-only
```

### Run specific benchmark file

```bash
poetry run pytest tests/benchmarks/bench_basic_analysis.py --benchmark-only
```

### Run specific benchmark test

```bash
poetry run pytest tests/benchmarks/bench_basic_analysis.py::TestBasicAnalysisBenchmarks::test_single_text_file_analysis --benchmark-only
```

### Run benchmarks with custom columns

```bash
poetry run pytest tests/benchmarks/ --benchmark-only --benchmark-columns=min,max,mean,median
```

### Save benchmark results

```bash
poetry run pytest tests/benchmarks/ --benchmark-only --benchmark-save=my_results
```

### Compare with previous results

```bash
poetry run pytest tests/benchmarks/ --benchmark-only --benchmark-compare=my_results
```

## Available Benchmarks

### bench_basic_analysis.py

Benchmarks for the `process_basic_analysis` function, which performs basic file metadata extraction:

- **test_single_text_file_analysis**: Analyzes a single text file
- **test_single_json_file_analysis**: Analyzes a single JSON file
- **test_single_zip_file_analysis**: Analyzes a single ZIP archive
- **test_analysis_by_file_size**: Tests analysis performance for files of different sizes (1KB, 10KB, 100KB)
- **test_batch_file_analysis**: Tests batch processing of multiple files (1, 10, 20 iterations)
- **test_hash_calculation_only**: Benchmarks just the hash calculation portion (MD5, SHA1, SHA256)
- **test_magic_type_detection**: Benchmarks magic type and MIME type detection
- **test_analysis_by_file_type**: Tests analysis for different file types (text, JSON, ZIP)
- **test_analysis_with_all_optional_fields**: Tests analysis with all optional metadata fields populated

## Benchmark Configuration

Benchmarks are configured in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "benchmark: performance benchmark tests"
]
# Skip benchmarks by default (use --benchmark-only to run them)
addopts = "--benchmark-skip"
# Test discovery patterns
testpaths = ["tests"]
python_files = ["test_*.py", "bench_*.py"]
```

This configuration:
- Skips benchmarks during normal test runs (only run with `--benchmark-only`)
- Enables pytest to discover `bench_*.py` files alongside regular `test_*.py` files
- Sets the test search path to the `tests/` directory

## Understanding Results

Benchmark results show:

- **Min**: Minimum execution time
- **Max**: Maximum execution time
- **Mean**: Average execution time
- **Median**: Median execution time
- **StdDev**: Standard deviation
- **IQR**: Interquartile range
- **Outliers**: Number of outlier measurements
- **OPS**: Operations per second (1 / Mean)
- **Rounds**: Number of benchmark rounds executed
- **Iterations**: Iterations per round

## Performance Expectations

Based on current benchmarks:

- Single file analysis: ~700 microseconds for small text files
- Hash calculation: ~28 microseconds for small files
- Batch processing scales roughly linearly with file count
- File size impacts performance (100KB files take ~5ms vs ~1.3ms for 1KB files)

## Adding New Benchmarks

When adding new benchmarks:

1. Create a new test file in `tests/benchmarks/` with prefix `bench_`
2. Use the `benchmark` fixture provided by pytest-benchmark
3. Follow the pattern from existing benchmarks:
   - Verify setup works before benchmarking
   - Use `benchmark(function, *args)` to run the benchmark
   - Assert results after benchmarking
4. Add parametrization for testing different scenarios
5. Use `benchmark.extra_info` to add context about test parameters

Example:

```python
def test_my_function(self, benchmark):
    # Setup
    test_data = create_test_data()

    # Verify setup works
    result = my_function(test_data)
    assert result is not None

    # Benchmark
    result = benchmark(my_function, test_data)

    # Verify result
    assert result.is_valid
```

## CI/CD Integration

To track performance over time, consider:

1. Running benchmarks on every commit
2. Saving results with `--benchmark-save`
3. Comparing against baseline with `--benchmark-compare`
4. Failing builds if performance degrades beyond threshold using `--benchmark-compare-fail`

## Notes

- Benchmarks are isolated from the main application to avoid Dapr initialization overhead
- Test fixtures are created in `tests/fixtures/` directory
- The `process_basic_analysis` function is duplicated in the benchmark file to avoid module-level side effects
