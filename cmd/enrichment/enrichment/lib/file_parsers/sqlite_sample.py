# Standard Libraries
import re
import sqlite3
from typing import Any, List

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog

logger = structlog.get_logger(module=__name__)


class sqlite_sample(Meta.FileType):
    def __init__(self, file_path: str, file_data: pb.FileDataEnriched, metadata: pb.Metadata):
        if type(file_data) == pb.FileDataEnriched:
            self.file_data = file_data
            self.metadata = metadata
            self.file_path = file_path
        else:
            raise Exception("Input was not a file_data object")

    def check_path(self) -> bool:
        """
        Returns True if the internal File path matches our target criteria.
        """
        if re.match(".*\\.(sqlite)$", self.file_data.path):
            return True
        else:
            return False

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        return "SQLite 3.x database" in helpers.get_magic_type(self.file_path)

    def _get_tables(self, cursor: sqlite3.Cursor) -> List[str]:
        """
        Returns a list of tables in the database.
        """
        table_query = "SELECT name FROM sqlite_master WHERE type='table';"
        cursor.execute(table_query)
        tables = cursor.fetchall()
        return [t[0] for t in tables]

    def _get_columns(self, cursor: sqlite3.Cursor, table: str) -> List[str]:
        """
        Returns a list of columns in the database.
        """
        col_data = cursor.execute(f"PRAGMA table_info({table});").fetchall()
        cols = [c[1] for c in col_data]
        return cols

    def _get_rows(self, cursor: sqlite3.Cursor, table: str, sample_size: int = 3) -> List[List[Any]]:
        """
        Returns a list of rows in the database.
        """
        cursor.execute(f"SELECT * FROM {table} LIMIT {sample_size};")
        data = cursor.fetchall()
        rows = [list(d) for d in data]
        return rows

    def _get_sample_data(self) -> dict:
        """
        Constructs sample data dictionary from database
        """
        ret = {}

        try:
            conn = sqlite3.connect(self.file_path)
            cursor = conn.cursor()

            tables = self._get_tables(cursor)
            for table in tables:
                cols = self._get_columns(cursor, table)
                rows = self._get_rows(cursor, table)
                ret[table] = {"schema": cols, "data": rows}

            conn.close()
            return ret
        except Exception as e:
            logger.exception(e, message="error parsing sqlite database", file_uuid=self.file_data.object_id)
            return {}

    def _format_sample_data(self, sample_data: dict) -> str:
        """
        Formats the sample data into a human-readable string.
        """
        ret = ""
        for table, data in sample_data.items():
            ret += f"Table: {table}\n"
            ret += f"Schema: {', '.join(data['schema'])}\n"
            ret += "Data: \n"
            for row in data["data"]:
                ret += f"\t{', '.join([str(r) for r in row])}\n"
        return ret

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses SQLite databases to extract table names, column names, and sample data.
        """
        data = self._get_sample_data()

        formatted_data = self._format_sample_data(data)

        parsed_data = pb.ParsedData()
        parsed_data.raw_parsed_data.data = formatted_data

        return (parsed_data, pb.AuthenticationDataIngestionMessage())
