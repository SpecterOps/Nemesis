"""Tests for the Parquet parser (audit #108): no pandas dependency, CSV headers aligned with data."""

import csv
import io
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from file_enrichment_modules.parquet import analyzer as parquet_analyzer
from file_enrichment_modules.parquet.analyzer import ParquetFileParser

from tests.harness import FileEnrichedFactory, ModuleTestHarness


def write_parquet(path: Path, table: pa.Table, **kwargs) -> Path:
    pq.write_table(table, path, **kwargs)
    return path


def pandas_style_table() -> pa.Table:
    """A table shaped like pandas' to_parquet output: data columns plus __index_level_0__ and pandas metadata."""
    table = pa.table(
        {
            "user": ["alice", "bob|smith", None],
            "count": [1, 2, 3],
            "__index_level_0__": [10, 11, 12],
        }
    )
    pandas_meta = {
        "index_columns": ["__index_level_0__"],
        "columns": [
            {"name": "user", "field_name": "user"},
            {"name": "count", "field_name": "count"},
            {"name": None, "field_name": "__index_level_0__"},
        ],
    }
    return table.replace_schema_metadata({b"pandas": json.dumps(pandas_meta).encode()})


async def run(path: Path):
    """Run the module, capturing the content of every uploaded transform (temp files are deleted after upload)."""
    harness = ModuleTestHarness()
    harness.register_file(
        object_id="pq",
        local_path=str(path),
        file_enriched=FileEnrichedFactory.create(
            object_id="pq", file_name=path.name, size=path.stat().st_size, magic_type="Apache Parquet"
        ),
    )
    uploads: dict[str, bytes] = {}
    async with harness.create_module(ParquetFileParser) as module:
        original = module.storage.upload_file

        def capture(file_path):
            object_id = original(file_path)
            uploads[str(object_id)] = Path(file_path).read_bytes()
            return object_id

        module.storage.upload_file = capture
        should = await module.should_process("pq", str(path))
        result = await module.process("pq", str(path))
    return should, result, uploads


def transform_content(result, uploads, transform_type) -> str:
    transform = next(t for t in result.transforms if t.type == transform_type)
    return uploads[transform.object_id].decode()


def test_module_does_not_import_pandas():
    source = Path(parquet_analyzer.__file__).read_text()
    assert "import pandas" not in source and "to_pandas" not in source


@pytest.mark.asyncio
async def test_csv_and_summary_for_simple_file(tmp_path):
    path = write_parquet(tmp_path / "simple.parquet", pa.table({"a": [1, 2], "b": ["x", None]}))
    should, result, uploads = await run(path)
    assert should is True
    assert result is not None
    rows = list(csv.reader(io.StringIO(transform_content(result, uploads, "parquet_to_csv"))))
    assert rows == [["a", "b"], ["1", "x"], ["2", ""]]
    summary = transform_content(result, uploads, "finding_summary")
    assert "Total rows: 2" in summary
    assert "| a | b |" in summary and "| 1 | x |" in summary


@pytest.mark.asyncio
async def test_pandas_index_column_stays_aligned(tmp_path):
    path = write_parquet(tmp_path / "pandas.parquet", pandas_style_table())
    _, result, uploads = await run(path)
    assert result is not None
    rows = list(csv.reader(io.StringIO(transform_content(result, uploads, "parquet_to_csv"))))
    assert rows[0] == ["user", "count", "__index_level_0__"]
    assert rows[1:] == [["alice", "1", "10"], ["bob|smith", "2", "11"], ["", "3", "12"]]
    summary = transform_content(result, uploads, "finding_summary")
    assert "| user | count | __index_level_0__ |" in summary
    assert "bob\\|smith" in summary  # pipes escaped in the markdown table


@pytest.mark.asyncio
async def test_multiple_row_groups_all_rows_written(tmp_path):
    table = pa.table({"n": list(range(25))})
    path = write_parquet(tmp_path / "groups.parquet", table, row_group_size=10)
    _, result, uploads = await run(path)
    rows = list(csv.reader(io.StringIO(transform_content(result, uploads, "parquet_to_csv"))))
    assert rows[0] == ["n"]
    assert [int(r[0]) for r in rows[1:]] == list(range(25))
    summary = transform_content(result, uploads, "finding_summary")
    assert "Row groups: 3" in summary
    # Sample shows at most 10 rows
    assert "| 9 |" in summary and "| 10 |" not in summary.split("## Row Group Details")[0]


@pytest.mark.asyncio
async def test_nested_and_binary_values(tmp_path):
    table = pa.table({"tags": [["a", "b"], []], "blob": [b"\x00\x01", None]})
    path = write_parquet(tmp_path / "nested.parquet", table)
    _, result, uploads = await run(path)
    rows = list(csv.reader(io.StringIO(transform_content(result, uploads, "parquet_to_csv"))))
    assert rows[0] == ["tags", "blob"]
    assert rows[1] == ["['a', 'b']", "b'\\x00\\x01'"]
    assert rows[2] == ["[]", ""]


@pytest.mark.asyncio
async def test_empty_file_has_header_and_no_sample(tmp_path):
    path = write_parquet(tmp_path / "empty.parquet", pa.table({"a": pa.array([], pa.int64())}))
    _, result, uploads = await run(path)
    assert result is not None
    rows = list(csv.reader(io.StringIO(transform_content(result, uploads, "parquet_to_csv"))))
    assert rows == [["a"]]
    assert "*No data available*" in transform_content(result, uploads, "finding_summary")


@pytest.mark.asyncio
async def test_not_a_parquet_file_returns_none(tmp_path):
    path = tmp_path / "bad.parquet"
    path.write_bytes(b"not parquet at all")
    _, result, _ = await run(path)
    assert result is None


@pytest.mark.asyncio
async def test_should_not_process_other_types(tmp_path):
    path = tmp_path / "x.txt"
    path.write_text("hello")
    harness = ModuleTestHarness()
    harness.register_file(
        object_id="txt",
        local_path=str(path),
        file_enriched=FileEnrichedFactory.create_plaintext_file(object_id="txt", file_name="x.txt"),
    )
    async with harness.create_module(ParquetFileParser) as module:
        assert await module.should_process("txt", str(path)) is False
