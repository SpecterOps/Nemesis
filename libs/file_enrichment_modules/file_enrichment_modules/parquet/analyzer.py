# enrichment_modules/parquet/analyzer.py
import csv
import os
import tempfile
from uuid import UUID

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

SAMPLE_ROWS = 10

# Decompression-bomb limits (#21). A few KB of parquet can declare billions of rows of an RLE/dictionary constant, so
# nothing reads a whole row group: rows are streamed in small batches and the CSV export stops at these caps.
CSV_BATCH_ROWS = 1_000
MAX_CSV_ROWS = 5_000_000
MAX_CSV_CELLS = 20_000_000  # rows x columns; bounds the time spent on wide all-constant files
MAX_CSV_BYTES = 512 * 1024**2  # CSV output
MAX_BATCH_BYTES = 256 * 1024**2  # estimated decoded size of one batch, checked before it is expanded
SAMPLE_CELL_CHARS = 200
# Skip the CSV entirely when the metadata declares more decoded data than this, or this much more than the file holds.
MAX_UNCOMPRESSED_BYTES = 4 * 1024**3
MAX_EXPANSION_RATIO = 100


def _batch_rows(batch):
    """Yield the rows of a pyarrow RecordBatch/Table as lists, in column order (pyarrow only, no pandas).

    Columns are read positionally, so the values always line up with the schema's column names, including
    pandas index columns such as ``__index_level_0__`` and duplicate names.
    """
    columns = [batch.column(i).to_pylist() for i in range(batch.num_columns)]
    return zip(*columns, strict=True)


def _dictionary_columns(schema: pa.Schema) -> list[str]:
    """String/binary columns, read dictionary-encoded so a repeated huge value is not copied once per row."""
    byte_types = (pa.types.is_string, pa.types.is_large_string, pa.types.is_binary, pa.types.is_large_binary)
    return [f.name for f in schema if any(check(f.type) for check in byte_types)]


def _decoded_size(batch: pa.RecordBatch) -> int:
    """Bytes the batch will take once dictionary columns are expanded, computed without expanding them."""
    total = 0
    for column in batch.columns:
        if pa.types.is_dictionary(column.type):
            lengths = pc.binary_length(column.dictionary)
            total += pc.sum(pc.take(lengths, column.indices)).as_py() or 0
            total += column.indices.nbytes
        else:
            total += column.nbytes
    return total


def _truncate_for_display(batch: pa.RecordBatch, limit: int = SAMPLE_CELL_CHARS) -> pa.RecordBatch:
    """Shorten string/binary values (via the dictionary when encoded) before they become Python objects."""
    columns = []
    for column in batch.columns:
        values = column.dictionary if pa.types.is_dictionary(column.type) else column
        if pa.types.is_string(values.type) or pa.types.is_large_string(values.type):
            values = pc.utf8_slice_codeunits(values, 0, limit)
        elif pa.types.is_binary(values.type) or pa.types.is_large_binary(values.type):
            values = pc.binary_slice(values, 0, limit)
        if pa.types.is_dictionary(column.type):
            column = pa.DictionaryArray.from_arrays(column.indices, values)
        else:
            column = values
        columns.append(column)
    return pa.RecordBatch.from_arrays(columns, names=batch.schema.names)


def _markdown_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return str(value)
    return str(value).replace("|", "\\|").replace("\n", " ")


class ParquetFileParser(EnrichmentModule):
    name: str = "parquet_file_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore

        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: UUID, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Check if file is a Parquet file
        return "apache parquet" in file_enriched.magic_type.lower()

    def _get_parquet_schema_info(self, schema):
        """Extract readable schema information from PyArrow schema."""
        schema_info = []
        for field in schema:
            schema_info.append({"name": field.name, "type": str(field.type), "nullable": field.nullable})
        return schema_info

    @staticmethod
    def _csv_skip_reason(file_metadata, file_size: int) -> str | None:
        """Reason to skip CSV export based on the declared (verified-on-decompress) uncompressed sizes, or None."""
        declared = sum(file_metadata.row_group(i).total_byte_size for i in range(file_metadata.num_row_groups))
        if declared > MAX_UNCOMPRESSED_BYTES:
            return f"declared uncompressed size {declared} bytes exceeds {MAX_UNCOMPRESSED_BYTES}"
        if file_size > 0 and declared > MAX_EXPANSION_RATIO * file_size:
            return (
                f"declared uncompressed size {declared} bytes is over {MAX_EXPANSION_RATIO}x "
                f"the file size ({file_size} bytes)"
            )
        return None

    @staticmethod
    def _write_csv(parquet_file, header: list[str], tmp_csv) -> str | None:
        """Stream all rows into ``tmp_csv``; return a truncation note if a limit stopped the export early."""
        writer = csv.writer(tmp_csv)
        writer.writerow(header)
        max_rows = min(MAX_CSV_ROWS, MAX_CSV_CELLS // max(1, len(header)))
        rows_written = 0
        batches = parquet_file.iter_batches(batch_size=CSV_BATCH_ROWS, use_pandas_metadata=False)
        for batch in batches:
            if batch.schema.names != header:
                raise ValueError(f"Batch columns {batch.schema.names} do not match schema {header}")
            remaining = max_rows - rows_written
            if batch.num_rows > remaining:
                batch = batch.slice(0, remaining)
            decoded = _decoded_size(batch)
            if decoded > MAX_BATCH_BYTES:
                return (
                    f"stopped after {rows_written} rows: the next {batch.num_rows} rows would decode to "
                    f"{decoded} bytes (limit {MAX_BATCH_BYTES})"
                )
            if tmp_csv.tell() + decoded > MAX_CSV_BYTES:
                return f"stopped after {rows_written} rows at the {MAX_CSV_BYTES}-byte CSV limit"
            writer.writerows(_batch_rows(batch))
            rows_written += batch.num_rows
            if rows_written >= max_rows:
                return f"stopped after {rows_written} rows (row limit {MAX_CSV_ROWS}, cell limit {MAX_CSV_CELLS})"
        return None

    def _analyze_parquet(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze Parquet file and generate enrichment result.

        Args:
            file_path: Path to the Parquet file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
        transforms = []

        try:
            # Read the Parquet file
            parquet_file = pq.ParquetFile(file_path)

            # Get metadata
            file_metadata = parquet_file.metadata
            num_rows = file_metadata.num_rows
            num_row_groups = file_metadata.num_row_groups
            schema = parquet_file.schema.to_arrow_schema()
            schema_info = self._get_parquet_schema_info(schema)
            # Re-open with string/binary columns kept dictionary-encoded for every data read below.
            dictionary_columns = _dictionary_columns(schema)
            data_file = (
                pq.ParquetFile(file_path, read_dictionary=dictionary_columns) if dictionary_columns else parquet_file
            )

            # Generate summary report
            report_lines = []

            # File summary
            report_lines.append("# Parquet File Summary")
            report_lines.append(f"\nFile name: {file_enriched.file_name}")
            report_lines.append(f"Total rows: {num_rows}")
            report_lines.append(f"Row groups: {num_row_groups}")

            # Schema information
            report_lines.append("\n## Schema")
            report_lines.append("\n| Column | Type | Nullable |")
            report_lines.append("| ------ | ---- | -------- |")
            for field in schema_info:
                report_lines.append(f"| {field['name']} | {field['type']} | {field['nullable']} |")

            # Sample data - stream only the first rows; reading a whole row group could expand a decompression bomb
            report_lines.append(f"\n## Sample Data (First {SAMPLE_ROWS} rows)")
            first_rows = (
                next(data_file.iter_batches(batch_size=SAMPLE_ROWS, use_pandas_metadata=False), None)
                if num_row_groups and num_rows
                else None
            )
            if first_rows is not None:
                first_rows = _truncate_for_display(first_rows)

            # Manually create markdown table to avoid tabulate dependency
            if first_rows is not None and first_rows.num_rows:
                report_lines.append("\n| " + " | ".join(_markdown_cell(col) for col in first_rows.column_names) + " |")
                report_lines.append("| " + " | ".join(["---"] * first_rows.num_columns) + " |")
                for row in _batch_rows(first_rows):
                    report_lines.append("| " + " | ".join(_markdown_cell(val) for val in row) + " |")
            else:
                report_lines.append("\n*No data available*")

            # Row group information
            report_lines.append("\n## Row Group Details")
            report_lines.append("\n| Group | Rows | Size (bytes) |")
            report_lines.append("| ----- | ---- | ------------ |")
            for i in range(num_row_groups):
                rg = file_metadata.row_group(i)
                report_lines.append(f"| {i} | {rg.num_rows} | {rg.total_byte_size} |")

            # Convert to CSV in small batches, within the decompression-bomb limits
            header = [field.name for field in schema]
            skip_reason = self._csv_skip_reason(file_metadata, os.path.getsize(file_path))
            truncated = None
            if skip_reason:
                logger.warning("Skipping Parquet CSV export", file_name=file_enriched.file_name, reason=skip_reason)
            else:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_csv:
                    truncated = self._write_csv(data_file, header, tmp_csv)
                    tmp_csv.flush()
                    csv_id = self.storage.upload_file(tmp_csv.name)

                    transforms.append(
                        Transform(
                            type="parquet_to_csv",
                            object_id=csv_id,
                            metadata={
                                "file_name": f"{file_enriched.file_name}.csv",
                                "offer_as_download": True,
                            },
                        )
                    )
                if truncated:
                    logger.warning("Parquet CSV export truncated", file_name=file_enriched.file_name, reason=truncated)

            report_lines.append("\n## CSV Export")
            if skip_reason:
                report_lines.append(f"\nCSV export skipped: {skip_reason}.")
            elif truncated:
                report_lines.append(f"\nCSV export truncated: {truncated}.")
            else:
                report_lines.append("\nAll rows exported.")

            # Create summary report transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                tmp_report.write("\n".join(report_lines))
                tmp_report.flush()
                report_id = self.storage.upload_file(tmp_report.name)

                transforms.insert(
                    0,
                    Transform(
                        type="finding_summary",
                        object_id=report_id,
                        metadata={
                            "file_name": f"{file_enriched.file_name}.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    ),
                )

            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing Parquet file for {file_enriched.file_name}")
            return None

    async def process(self, object_id: UUID, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Parquet file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_parquet(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_parquet(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing Parquet file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return ParquetFileParser()
