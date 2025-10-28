# enrichment_modules/parquet/analyzer.py
import csv
import tempfile

import pyarrow.parquet as pq
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class ParquetFileParser(EnrichmentModule):
    name: str = "parquet_file_parser"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = await get_file_enriched_async(object_id)

        # Check if file is a Parquet file
        return "apache parquet" in file_enriched.magic_type.lower()

    def _get_parquet_schema_info(self, schema):
        """Extract readable schema information from PyArrow schema."""
        schema_info = []
        for field in schema:
            schema_info.append({"name": field.name, "type": str(field.type), "nullable": field.nullable})
        return schema_info

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

            # Sample data - first 10 rows
            first_rows = parquet_file.read_row_group(0).to_pandas().head(10)
            report_lines.append("\n## Sample Data (First 10 rows)")

            # Manually create markdown table to avoid tabulate dependency
            if not first_rows.empty:
                # Add column headers
                report_lines.append("\n| " + " | ".join(str(col) for col in first_rows.columns) + " |")
                # Add separator line
                report_lines.append("| " + " | ".join(["---"] * len(first_rows.columns)) + " |")
                # Add data rows
                for _, row in first_rows.iterrows():
                    # Handle different data types and null values
                    row_values = []
                    for val in row:
                        if val is None:
                            row_values.append("")
                        elif isinstance(val, (int, float, bool)):
                            row_values.append(str(val))
                        else:
                            # Escape pipe characters in string values
                            row_values.append(str(val).replace("|", "\\|"))
                    report_lines.append("| " + " | ".join(row_values) + " |")
            else:
                report_lines.append("\n*No data available*")

            # Row group information
            report_lines.append("\n## Row Group Details")
            report_lines.append("\n| Group | Rows | Size (bytes) |")
            report_lines.append("| ----- | ---- | ------------ |")
            for i in range(num_row_groups):
                rg = file_metadata.row_group(i)
                report_lines.append(f"| {i} | {rg.num_rows} | {rg.total_byte_size} |")

            # Create summary report transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                tmp_report.write("\n".join(report_lines))
                tmp_report.flush()
                report_id = self.storage.upload_file(tmp_report.name)

                transforms.append(
                    Transform(
                        type="finding_summary",
                        object_id=f"{report_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    )
                )

            # Convert to CSV efficiently using chunking
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_csv:
                writer = csv.writer(tmp_csv)

                # Write header (column names)
                writer.writerow([field.name for field in schema])

                # Process each row group to handle large files
                chunksize = 100000  # Number of rows to process at a time
                for i in range(num_row_groups):
                    # Read a row group
                    table = parquet_file.read_row_group(i)

                    # Process in batches to minimize memory usage
                    for batch in table.to_batches(max_chunksize=chunksize):
                        # Convert to pandas for easier row iteration
                        batch_df = batch.to_pandas()

                        # Write rows
                        writer.writerows(batch_df.values.tolist())

                    # Free memory
                    del table

                tmp_csv.flush()
                csv_id = self.storage.upload_file(tmp_csv.name)

                transforms.append(
                    Transform(
                        type="parquet_to_csv",
                        object_id=f"{csv_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception as e:
            logger.exception(e, message=f"Error analyzing Parquet file for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Parquet file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = await get_file_enriched_async(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_parquet(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_parquet(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing Parquet file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return ParquetFileParser()
