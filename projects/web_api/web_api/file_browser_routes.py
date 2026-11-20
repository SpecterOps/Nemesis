"""
File browser queries over `file_listings` / `file_linkings`.

The frontend File Browser used to download every listing row of a source (and, per folder, the
whole subtree below it) and build the tree in the browser, which does not work with hundreds of
thousands of listings per source. These helpers return one folder level at a time:

- files directly inside a folder come from an index range scan on
  idx_file_listings_browse (source, file_listing_parent(path) COLLATE "C", path), paged with a
  keyset cursor (the last path returned);
- sub-folders are enumerated with a "loose index scan" (recursive CTE) over the same index: one
  index probe per distinct child folder, independent of how many files live below it.

Folder paths are the UI form: leading slashes stripped, '/'-separated, '' for the root.
"""

from typing import Any

from psycopg import Connection
from psycopg.rows import TupleRow
from psycopg_pool import ConnectionPool

DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000
MAX_FOLDERS = 5000

COLLECTION_STATUS = "needs_to_be_collected"

PARENT = 'file_listing_parent(path) COLLATE "C"'


def _normalize_folder(path: str | None) -> str:
    return (path or "").strip("/")


def _like_escape(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_sources(pool: ConnectionPool[Connection[TupleRow]]) -> list[dict[str, Any]]:
    """All file listing sources with total and per-status counts."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT source, status, COUNT(*) FROM file_listings GROUP BY source, status ORDER BY source")
            sources: dict[str, dict[str, Any]] = {}
            for source, status, count in cur.fetchall():
                entry = sources.setdefault(source, {"source": source, "total_files": 0, "status_counts": {}})
                entry["total_files"] += count
                entry["status_counts"][status] = count
    return list(sources.values())


def _child_folders(cur, source: str, folder: str, max_folders: int) -> tuple[list[str], bool]:
    """Names of the immediate sub-folders of `folder` (C/byte order), and whether the list was truncated."""
    if folder:
        lower = folder + "/"  # descendants' parents are 'folder/...'
        upper = folder + "0"  # '0' is the byte after '/'
        offset = len(folder) + 2  # 1-based start of the part after 'folder/'
        range_cond = f"{PARENT} > %(lower)s AND {PARENT} < %(upper)s"
        params: dict[str, Any] = {"source": source, "lower": lower, "upper": upper}
    else:
        offset = 1
        range_cond = f"{PARENT} > ''"
        params = {"source": source}

    # child(p) = first path segment of parent p below `folder`; full child path = folder/child.
    child_expr = "split_part(substr({p}, %(offset)s), '/', 1)"
    params["offset"] = offset
    params["prefix"] = folder + "/" if folder else ""
    # Each child folder c contributes up to 2 visits: a parent equal to prefix||c (c holds files) and
    # parents under prefix||c||'/' (deeper folders). In byte order those two ranges are not adjacent
    # (siblings such as 'c-x' or 'c.y' sort in between), so step monotonically:
    #   - from a parent equal to prefix||c   -> the next strictly greater parent;
    #   - from a parent inside prefix||c||'/' -> the first parent >= prefix||c||'0' ('0' follows '/').
    params["max_steps"] = 2 * max_folders + 2
    child_of_w = child_expr.format(p="w.parent")
    cur.execute(
        f"""
        WITH RECURSIVE walk(parent, n) AS (
            (SELECT {PARENT}, 1 FROM file_listings
             WHERE source = %(source)s AND {range_cond}
             ORDER BY {PARENT} LIMIT 1)
            UNION ALL
            SELECT CASE
                       WHEN w.parent = %(prefix)s || {child_of_w} THEN
                           (SELECT {PARENT} FROM file_listings
                            WHERE source = %(source)s AND {range_cond} AND {PARENT} > w.parent
                            ORDER BY {PARENT} LIMIT 1)
                       ELSE
                           (SELECT {PARENT} FROM file_listings
                            WHERE source = %(source)s AND {range_cond}
                              AND {PARENT} >= %(prefix)s || {child_of_w} || '0'
                            ORDER BY {PARENT} LIMIT 1)
                   END,
                   w.n + 1
            FROM walk w
            WHERE w.parent IS NOT NULL AND w.n < %(max_steps)s
        )
        SELECT {child_expr.format(p="parent")} FROM walk WHERE parent IS NOT NULL
        """,
        params,
    )
    rows = cur.fetchall()
    names = list(dict.fromkeys(row[0] for row in rows))
    names.sort(key=lambda name: (name.lower(), name))
    truncated = len(rows) >= params["max_steps"] or len(names) > max_folders
    return names[:max_folders], truncated


def list_children(
    pool: ConnectionPool[Connection[TupleRow]],
    source: str,
    path: str | None = None,
    cursor: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    search: str | None = None,
) -> dict[str, Any]:
    """One level of the file tree: sub-folders (first page only) and a page of files."""
    folder = _normalize_folder(path)
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    search = (search or "").strip()

    file_conds = ["source = %(source)s", f"{PARENT} = %(folder)s"]
    params: dict[str, Any] = {"source": source, "folder": folder, "limit": limit + 1}
    if search:
        file_conds.append("regexp_replace(path, '^.*/', '') ILIKE %(pattern)s")
        params["pattern"] = f"%{_like_escape(search)}%"
    where = " AND ".join(file_conds)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            folders: list[dict[str, str]] = []
            folders_truncated = False
            if cursor is None:
                names, folders_truncated = _child_folders(cur, source, folder, MAX_FOLDERS)
                if search:
                    needle = search.lower()
                    names = [name for name in names if needle in name.lower()]
                folders = [{"name": name, "path": f"{folder}/{name}" if folder else name} for name in names]

            cur.execute(f"SELECT COUNT(*) FROM file_listings WHERE {where}", params)
            count_row = cur.fetchone()
            total_files = count_row[0] if count_row else 0

            page_where = where
            if cursor is not None:
                page_where += " AND path > %(cursor)s"
                params["cursor"] = cursor
            cur.execute(
                f"""
                SELECT path, object_id, status FROM file_listings
                WHERE {page_where}
                ORDER BY path
                LIMIT %(limit)s
                """,
                params,
            )
            rows = cur.fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    files = [
        {
            "name": db_path.rstrip("/").rsplit("/", 1)[-1],
            "path": db_path,
            "object_id": str(object_id) if object_id else None,
            "status": status,
        }
        for db_path, object_id, status in rows
    ]
    return {
        "source": source,
        "path": folder,
        "folders": folders,
        "folders_truncated": folders_truncated,
        "files": files,
        "total_files": total_files,
        "next_cursor": files[-1]["path"] if has_more and files else None,
    }


def list_collection_paths(
    pool: ConnectionPool[Connection[TupleRow]],
    source: str,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_SIZE,
    search: str | None = None,
) -> dict[str, Any]:
    """A page of the paths that still need collecting, with the linkings that require them."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    offset = max(0, offset)
    search = (search or "").strip()

    conds = ["source = %(source)s", "status = %(status)s"]
    params: dict[str, Any] = {"source": source, "status": COLLECTION_STATUS, "limit": limit, "offset": offset}
    if search:
        conds.append("path ILIKE %(pattern)s")
        params["pattern"] = f"%{_like_escape(search)}%"
    where = " AND ".join(conds)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM file_listings WHERE {where}", params)
            count_row = cur.fetchone()
            total = count_row[0] if count_row else 0

            cur.execute(
                f"SELECT path FROM file_listings WHERE {where} ORDER BY path LIMIT %(limit)s OFFSET %(offset)s",
                params,
            )
            paths = [row[0] for row in cur.fetchall()]

            linkings: dict[str, list[dict[str, Any]]] = {}
            if paths:
                cur.execute(
                    """
                    SELECT lk.file_path_2, lk.file_path_1, lk.link_type, fl.object_id
                    FROM file_linkings lk
                    LEFT JOIN file_listings fl
                      ON fl.source = lk.source AND fl.path = lk.file_path_1 AND fl.status = 'collected'
                    WHERE lk.source = %s AND lk.file_path_2 = ANY(%s)
                    ORDER BY lk.linking_id
                    """,
                    [source, paths],
                )
                for required_path, required_by, link_type, object_id in cur.fetchall():
                    linkings.setdefault(required_path, []).append(
                        {
                            "requiredBy": required_by,
                            "requiredByObjectId": str(object_id) if object_id else None,
                            "reason": link_type,
                        }
                    )

    return {
        "source": source,
        "total": total,
        "offset": offset,
        "limit": limit,
        "paths": [{"path": p, "linkings": linkings.get(p, [])} for p in paths],
    }
