# enrichment_modules/sqlite/analyzer.py
import base64
import sqlite3
import tempfile
from typing import Any

from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


def safe_str_conversion(value: Any) -> str:
    """Safely convert any value to a string representation."""
    if value is None:
        return "NULL"

    # If it's already a string, try to return it directly
    if isinstance(value, str):
        try:
            return value
        except UnicodeDecodeError:
            pass

    # For bytes, try to decode as UTF-8, fallback to base64
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary:{base64.b64encode(value).decode('ascii')}>"

    # For other types, use default string conversion
    return str(value)


def get_table_data(cursor: sqlite3.Cursor, table: str, sample_size: int = 3) -> dict:
    """Get schema and sample data for a single table."""
    try:
        # Get columns
        col_data = cursor.execute(f"PRAGMA table_info({table});").fetchall()
        columns = [c[1] for c in col_data]
        column_types = [c[2] for c in col_data]

        # Get sample rows with proper type handling
        cursor.execute(f"SELECT * FROM {table} LIMIT {sample_size};")
        raw_data = cursor.fetchall()

        # Convert each value safely to string
        rows = []
        for row in raw_data:
            safe_row = [safe_str_conversion(value) for value in row]
            rows.append(safe_row)

        return {"schema": columns, "column_types": column_types, "data": rows}
    except sqlite3.OperationalError as e:
        logger.warning(f"Error getting data for table {table}: {str(e)}")
        return {"schema": [], "column_types": [], "data": [], "error": str(e)}


def format_sqlite_data(database_data: dict) -> str:
    """Format SQLite data into a human-readable string."""
    output = []
    for table, data in database_data.items():
        output.append(f"Table: {table}")

        if "error" in data:
            output.append(f"Error reading table: {data['error']}")
            output.append("")
            continue

        # Show schema with column types
        schema_with_types = [f"{col} ({type_})" for col, type_ in zip(data["schema"], data["column_types"])]
        output.append(f"Schema: {', '.join(schema_with_types)}")

        output.append("Data:")
        for row in data["data"]:
            # Handle potentially long binary data by truncating
            formatted_row = []
            for value in row:
                if value.startswith("<binary:"):
                    formatted_value = value[:50] + "..." if len(value) > 50 else value
                else:
                    formatted_value = value
                formatted_row.append(formatted_value)
            output.append(f"   {', '.join(formatted_row)}")
        output.append("")  # Empty line between tables

    return "\n".join(output)


class SqliteParser(EnrichmentModule):
    def __init__(self):
        super().__init__("sqlite_parser")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)
        should_run = (
            "sqlite 3.x database" in file_enriched.magic_type.lower()
            or file_enriched.file_name.lower().endswith(".sqlite")
        )
        return should_run

    def _analyze_sqlite_database(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze SQLite database file and generate enrichment result.

        Args:
            file_path: Path to the SQLite database file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(file_path)
            # Handle binary data properly to avoid UTF-8 decode errors
            conn.text_factory = lambda x: x.decode("utf-8", errors="replace") if isinstance(x, bytes) else x
            cursor = conn.cursor()

            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()]

            # Process each table
            database_data = {}
            for table in tables:
                database_data[table] = get_table_data(cursor, table)

            conn.close()
            # Store the raw parsed data
            enrichment_result.results = database_data

            # Create human-readable display
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                display = format_sqlite_data(database_data)
                tmp_display_file.write(display)
                tmp_display_file.flush()

                object_id = self.storage.upload_file(tmp_display_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )
            enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception as e:
            logger.exception(e, message=f"Error analyzing SQLite database for {file_enriched.file_name}")
            return None

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process SQLite database file using the state store.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = get_file_enriched(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_sqlite_database(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_sqlite_database(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing SQLite database")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return SqliteParser()
