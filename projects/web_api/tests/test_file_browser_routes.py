"""Tests for the file browser queries (web_api.file_browser_routes) with a fake database."""

import uuid
from unittest.mock import patch

from fake_db import FakePool
from web_api import file_browser_routes as fb


def test_list_sources_groups_status_counts():
    pool = FakePool([[("A", "collected", 3), ("A", "not_exists", 2), ("B", "needs_to_be_collected", 1)]])
    assert fb.list_sources(pool) == [
        {"source": "A", "total_files": 5, "status_counts": {"collected": 3, "not_exists": 2}},
        {"source": "B", "total_files": 1, "status_counts": {"needs_to_be_collected": 1}},
    ]


def test_list_sources_empty():
    assert fb.list_sources(FakePool([[]])) == []


def test_list_children_root_first_page():
    oid = uuid.uuid4()
    pool = FakePool(
        [
            [("Users",), ("data",), ("data",), ("Users",)],  # folder walk (children may repeat)
            [(2,)],  # file count
            [("/top.txt", oid, "collected"), ("other", None, "not_exists")],
        ]
    )
    result = fb.list_children(pool, "S", "", limit=10)
    assert [f["name"] for f in result["folders"]] == ["data", "Users"]  # deduped, case-insensitive order
    assert result["folders"][0]["path"] == "data"
    assert result["files"] == [
        {"name": "top.txt", "path": "/top.txt", "object_id": str(oid), "status": "collected"},
        {"name": "other", "path": "other", "object_id": None, "status": "not_exists"},
    ]
    assert result["total_files"] == 2
    assert result["next_cursor"] is None
    assert result["folders_truncated"] is False
    walk_sql, walk_params = pool.executed[0]
    assert "WITH RECURSIVE" in walk_sql
    assert walk_params["prefix"] == ""


def test_list_children_subfolder_paths_and_paging():
    rows = [(f"/a/b/f{i}", None, "collected") for i in range(3)]
    pool = FakePool([[("c",)], [(10,)], rows])
    result = fb.list_children(pool, "S", "/a/b/", limit=2)
    assert result["path"] == "a/b"
    assert result["folders"] == [{"name": "c", "path": "a/b/c"}]
    assert len(result["files"]) == 2
    assert result["next_cursor"] == "/a/b/f1"
    walk_params = pool.executed[0][1]
    assert walk_params["lower"] == "a/b/" and walk_params["upper"] == "a/b0"
    assert walk_params["offset"] == len("a/b") + 2
    file_sql, file_params = pool.executed[2]
    assert file_params["folder"] == "a/b"
    assert file_params["limit"] == 3  # one extra row to detect another page


def test_list_children_with_cursor_skips_folders():
    pool = FakePool([[(5,)], [("/a/z", None, "collected")]])
    result = fb.list_children(pool, "S", "a", cursor="/a/y", limit=2)
    assert result["folders"] == []
    assert result["next_cursor"] is None
    sql, params = pool.executed[1]
    assert "path > %(cursor)s" in sql
    assert params["cursor"] == "/a/y"


def test_list_children_search_filters_and_escapes():
    pool = FakePool([[("abc",), ("xyz",)], [(0,)], []])
    result = fb.list_children(pool, "S", "", search="  b_% ")
    # folder names are filtered in Python, case-insensitively, on the raw term
    assert result["folders"] == []
    pool = FakePool([[("ABC",), ("xyz",)], [(0,)], []])
    result = fb.list_children(pool, "S", "", search="b")
    assert [f["name"] for f in result["folders"]] == ["ABC"]
    count_sql, params = pool.executed[1]
    assert "ILIKE %(pattern)s" in count_sql
    pool = FakePool([[], [(0,)], []])
    fb.list_children(pool, "S", "", search="50%_off\\")
    assert pool.executed[1][1]["pattern"] == "%50\\%\\_off\\\\%"


def test_list_children_limit_is_clamped():
    pool = FakePool([[], [(0,)], []])
    fb.list_children(pool, "S", "", limit=100000)
    assert pool.executed[2][1]["limit"] == fb.MAX_PAGE_SIZE + 1
    pool = FakePool([[], [(0,)], []])
    fb.list_children(pool, "S", "", limit=0)
    assert pool.executed[2][1]["limit"] == 2


def test_list_children_reports_truncated_folders():
    names = [(f"d{i}",) for i in range(5)]
    pool = FakePool([names, [(0,)], []])
    with patch.object(fb, "MAX_FOLDERS", 3):
        result = fb.list_children(pool, "S", "")
    assert result["folders_truncated"] is True
    assert len(result["folders"]) == 3


def test_list_collection_paths_with_linkings():
    oid = uuid.uuid4()
    pool = FakePool(
        [
            [(3,)],
            [("/x/need1",), ("/x/need2",)],
            [("/x/need1", "/x/req.dll", "dll", oid), ("/x/need1", "/x/other.exe", "exe", None)],
        ]
    )
    result = fb.list_collection_paths(pool, "S", offset=0, limit=2)
    assert result["total"] == 3
    assert result["paths"] == [
        {
            "path": "/x/need1",
            "linkings": [
                {"requiredBy": "/x/req.dll", "requiredByObjectId": str(oid), "reason": "dll"},
                {"requiredBy": "/x/other.exe", "requiredByObjectId": None, "reason": "exe"},
            ],
        },
        {"path": "/x/need2", "linkings": []},
    ]
    link_sql, link_params = pool.executed[2]
    assert link_params == ["S", ["/x/need1", "/x/need2"]]


def test_list_collection_paths_empty_page_skips_linkings_query():
    pool = FakePool([[(0,)], []])
    result = fb.list_collection_paths(pool, "S", offset=-5, search="abc")
    assert result["paths"] == [] and result["total"] == 0 and result["offset"] == 0
    assert len(pool.executed) == 2
    assert pool.executed[0][1]["pattern"] == "%abc%"


# ---------------------------------------------------------------- endpoints


def test_children_endpoint(client):
    payload = {"folders": [], "files": [], "total_files": 0, "next_cursor": None}
    with (
        patch("web_api.main.get_db_pool"),
        patch("web_api.file_browser_routes.list_children", return_value=payload) as mock_list,
    ):
        response = client.get("/file-browser/children", params={"source": "S", "path": "a/b", "limit": 50})
    assert response.status_code == 200
    assert response.json() == payload
    args = mock_list.call_args.args
    assert args[1:] == ("S", "a/b", None, 50, None)


def test_children_endpoint_validation(client):
    assert client.get("/file-browser/children").status_code == 422  # source required
    assert client.get("/file-browser/children", params={"source": "S", "limit": 5000}).status_code == 422


def test_collection_endpoint_error(client):
    with (
        patch("web_api.main.get_db_pool"),
        patch("web_api.file_browser_routes.list_collection_paths", side_effect=RuntimeError("boom")),
    ):
        response = client.get("/file-browser/collection", params={"source": "S"})
    assert response.status_code == 500


def test_sources_endpoint(client):
    with patch("web_api.main.get_db_pool"), patch("web_api.file_browser_routes.list_sources", return_value=[]):
        response = client.get("/file-browser/sources")
    assert response.status_code == 200
    assert response.json() == []
