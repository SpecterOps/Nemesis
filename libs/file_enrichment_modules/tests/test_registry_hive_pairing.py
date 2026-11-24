"""Hive pairing (#39): lookups stay within the uploading file's project and source, and the fallback only pairs
hives that sit in the same directory."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from file_enrichment_modules.registry_hive.analyzer import RegistryHiveAnalyzer, _parent_dir

SAM_ID = "11111111-1111-1111-1111-111111111111"


class FakeConn:
    """Answers the two pairing queries from an in-memory list of files, honoring source/project/path filters."""

    def __init__(self, files):
        self.files = files
        self.queries = []

    async def fetchrow(self, query, source, project, path):
        self.queries.append((query, (source, project, path)))
        matches = [
            f
            for f in self.files
            if f["source"] == source
            and f["project"] == project
            and f["path"].replace("\\", "/").lower() == path.lower()
        ]
        return {"object_id": matches[0]["object_id"]} if matches else None

    async def fetch(self, query, source, project, hive_type_json):
        self.queries.append((query, (source, project, hive_type_json)))
        return [
            {"object_id": f["object_id"], "path": f["path"]}
            for f in self.files
            if f["source"] == source and f["project"] == project and f'"{f["hive_type"]}"' == hive_type_json
        ]


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return Ctx()


@pytest.fixture
def make_analyzer():
    def build(files):
        with patch("file_enrichment_modules.registry_hive.analyzer.StorageMinio"):
            analyzer = RegistryHiveAnalyzer()
        analyzer.storage = MagicMock()
        conn = FakeConn(files)
        analyzer.asyncpg_pool = FakePool(conn)
        return analyzer, conn

    return build


def uploaded(path, project="proj-b", source="host://WS01"):
    return SimpleNamespace(path=path, project=project, source=source)


def hive(path, project="proj-a", source="host://WS01", hive_type="SAM", object_id=SAM_ID):
    return {"object_id": object_id, "path": path, "project": project, "source": source, "hive_type": hive_type}


@pytest.mark.asyncio
async def test_standard_path_in_another_project_is_not_paired(make_analyzer):
    analyzer, conn = make_analyzer([hive("C:\\Windows\\System32\\Config\\SAM", project="proj-a")])
    found = await analyzer._find_existing_hive(
        uploaded("C:\\Windows\\System32\\Config\\SYSTEM", project="proj-b"), "C:/Windows/System32/Config/SAM"
    )
    assert found is None
    # Both lookups were scoped to the uploading file's project.
    assert all(params[1] == "proj-b" for _, params in conn.queries)
    assert all("project IS NOT DISTINCT FROM" in query for query, _ in conn.queries)


@pytest.mark.asyncio
async def test_fallback_in_another_project_is_not_paired(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\loot\\SAM", project="proj-a")])
    assert await analyzer._find_existing_hive(uploaded("C:\\loot\\SYSTEM"), "C:/Windows/System32/Config/SAM") is None


@pytest.mark.asyncio
async def test_standard_path_same_project_pairs_with_backslashes(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\Windows\\System32\\Config\\SAM", project="proj-b")])
    found = await analyzer._find_existing_hive(
        uploaded("C:\\Windows\\System32\\Config\\SYSTEM"), "C:/Windows/System32/Config/SAM"
    )
    assert found == SAM_ID


@pytest.mark.asyncio
async def test_fallback_same_directory_pairs(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\Loot\\WS01\\sam.save", project="proj-b")])
    found = await analyzer._find_existing_hive(uploaded("c:/loot/ws01/system.save"), "C:/Windows/System32/Config/SAM")
    assert found == SAM_ID


@pytest.mark.asyncio
async def test_fallback_other_directory_not_paired(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\Loot\\WS02\\sam.save", project="proj-b")])
    assert await analyzer._find_existing_hive(uploaded("C:\\Loot\\WS01\\system.save"), "C:/x/SAM") is None


@pytest.mark.asyncio
async def test_fallback_other_source_not_paired(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\loot\\SAM", project="proj-b", source="host://WS02")])
    assert await analyzer._find_existing_hive(uploaded("C:\\loot\\SYSTEM"), "C:/x/SAM") is None


@pytest.mark.asyncio
async def test_fallback_wrong_hive_type_not_paired(make_analyzer):
    analyzer, _ = make_analyzer([hive("C:\\loot\\SECURITY", project="proj-b", hive_type="SECURITY")])
    assert await analyzer._find_existing_hive(uploaded("C:\\loot\\SYSTEM"), "C:/x/SAM") is None


@pytest.mark.asyncio
async def test_no_directory_no_fallback(make_analyzer):
    analyzer, conn = make_analyzer([hive("SAM", project="proj-b")])
    assert await analyzer._find_existing_hive(uploaded("SYSTEM"), "C:/x/SAM") is None
    assert len(conn.queries) == 1  # only the exact-path lookup ran


@pytest.mark.asyncio
async def test_no_pool_returns_none(make_analyzer):
    analyzer, _ = make_analyzer([])
    analyzer.asyncpg_pool = None
    assert await analyzer._find_existing_hive(uploaded("C:\\loot\\SYSTEM"), "C:/x/SAM") is None


@pytest.mark.asyncio
async def test_database_error_returns_none(make_analyzer):
    analyzer, conn = make_analyzer([])

    async def boom(*args):
        raise RuntimeError("db down")

    conn.fetchrow = boom
    assert await analyzer._find_existing_hive(uploaded("C:\\loot\\SYSTEM"), "C:/x/SAM") is None


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("C:\\Windows\\System32\\Config\\SAM", "c:/windows/system32/config"),
        ("/mnt/img/Windows/System32/config/SAM", "/mnt/img/windows/system32/config"),
        ("SAM", None),
        (None, None),
    ],
)
def test_parent_dir(path, expected):
    assert _parent_dir(path) == expected
