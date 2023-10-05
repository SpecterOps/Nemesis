# Standard Libraries
import os
import re
import urllib.parse
from typing import Tuple

# 3rd Party Libraries
import humanize
import streamlit as st

# Adapted from https://github.com/chiachong/medium-search-app/blob/9fde32173731d4f696fdee05454314277504d89f/srcs/streamlit_app/templates.py


PUBLIC_KIBANA_URL = os.environ.get("PUBLIC_KIBANA_URL")
WEB_API_URL = os.environ.get("WEB_API_URL")
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER").rstrip("/")


def no_result_html() -> str:
    """ """
    return """
        <div style="color:grey;font-size:95%;margin-top:0.5em;">
            No results were found.
        </div><br>
    """


def number_of_results(total_hits: int, duration: float = -1.0) -> str:
    """HTML scripts to display number of results and time taken."""
    if duration < 0:
        return f"""
            <div style="color:grey;font-size:95%;">
                {total_hits} results
            </div><br>
        """
    else:
        return f"""
            <div style="color:grey;font-size:95%;">
                {total_hits} results ({duration:.2f} seconds)
            </div><br>
        """


def text_pagination(total_pages: int, search: str, current_page: int) -> str:
    """Create and return html for text search pagination."""

    # search words
    params = f"?text_search={urllib.parse.quote(search)}"

    # avoid invalid page number (<=0)
    if (current_page - 5) > 0:
        start_from = current_page - 5
    else:
        start_from = 1

    hrefs = []
    if current_page != 1:
        hrefs.append(f'<a href="{params}&text_page={1}" target="_self">&lt&ltFirst</a>')
        hrefs.append(f'<a href="{params}&text_page={current_page - 1}" target="_self">&ltPrevious</a>')

    for i in range(start_from, min(total_pages + 1, start_from + 10)):
        if i == current_page:
            hrefs.append(f"{current_page}")
        else:
            hrefs.append(f'<a href="{params}&text_page={i}" target="_self">{i}</a>')

    if current_page != total_pages:
        hrefs.append(f'<a href="{params}&text_page={current_page + 1}" target="_self">Next&gt</a>')

    return "<div>" + "&emsp;".join(hrefs) + "</div>"


def file_pagination(total_pages: int, current_page: int, search_params: dict) -> str:
    """Create and return html for file pagination."""

    params = "".join([f"&{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}" for k, v in search_params.items() if v])

    # avoid invalid page number (<=0)
    if (current_page - 5) > 0:
        start_from = current_page - 5
    else:
        start_from = 1

    hrefs = []
    if current_page != 1:
        hrefs.append(f'<a href="?{params}&file_download_page={1}" target="_self">&lt&ltFirst</a>')
        hrefs.append(f'<a href="?{params}&file_download_page={current_page - 1}" target="_self">&ltPrevious</a>')

    for i in range(start_from, min(total_pages + 1, start_from + 10)):
        if i == current_page:
            hrefs.append(f"{current_page}")
        else:
            hrefs.append(f'<a href="?{params}&file_download_page={i}" target="_self">{i}</a>')

    if current_page != total_pages:
        hrefs.append(f'<a href="?{params}&file_download_page={current_page + 1}" target="_self">Next&gt</a>')

    hrefs.insert(0, f'<a href="?{params}&file_download_page={current_page}" target="_self">Current Page Link</a>')

    return "<div>" + "&emsp;".join(hrefs) + "</div>"


def np_pagination(total_pages: int, current_page: int) -> str:
    """Create and return html for NoseyParker pagination."""

    # avoid invalid page number (<=0)
    if (current_page - 5) > 0:
        start_from = current_page - 5
    else:
        start_from = 1

    hrefs = []
    if current_page != 1:
        hrefs.append(f'<a href="?np_page={1}" target="_self">&lt&ltFirst</a>')
        hrefs.append(f'<a href="?np_page={current_page - 1}" target="_self">&ltPrevious</a>')

    for i in range(start_from, min(total_pages + 1, start_from + 10)):
        if i == current_page:
            hrefs.append(f"{current_page}")
        else:
            hrefs.append(f'<a href="?np_page={i}" target="_self">{i}</a>')

    if current_page != total_pages:
        hrefs.append(f'<a href="?np_page={current_page + 1}" target="_self">Next&gt</a>')

    return "<div>" + "&emsp;".join(hrefs) + "</div>"


def text_search_result(i: int, url: str, pdf_url: str, source: str, path: str, highlights: str, length: str, originating_object_id: str, **kwargs) -> Tuple[str, str, str]:
    """HTML scripts to display text search results."""

    view_file_url = f"{NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={originating_object_id}"

    return (
        f"""
        <div style="font-size:120%;">
            {i + 1}.
            <a href="{view_file_url}">
                {path}
            </a>
        </div>
        <div style="font-size:95%;">
            <div style="color:grey;font-size:95%;">
                {length} words
                &nbsp;
                <a href="{pdf_url}">
                    PDF Link
                </a>
            </div>
            <pre>""",
        highlights,
        """</pre>
        </div>
    """,
    )


def sourcecode_search_result(i: int, object_id: str, download_url: str, source: str, path: str, name: str, language: str, highlights: str, size: str, **kwargs) -> Tuple[str, str, str]:
    """HTML scripts to display text search results."""

    view_file_url = f"{NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={object_id}"

    return (
        f"""
        <div style="font-size:120%;">
            {i + 1}.
            <a href="{view_file_url}">
                {path}
            </a>
        </div>
        <div style="font-size:95%;">
            <div style="color:grey;font-size:95%;">
                <b>Language: {language}</b>
                &nbsp;
                Size: {humanize.naturalsize(size)}
            </div>
            <pre>""",
        highlights,
        """</pre>
        </div>
    """,
    )


def semantic_search_result(result) -> Tuple[str, str, str]:
    """HTML scripts to display a semantic search json result."""

    text = result["text"]
    score = result["score"]
    source = ""
    if "source" in result:
        source = result["source"]

    originating_object_id = result["originating_object_id"]
    originating_object_path = result["originating_object_path"]
    pdf_object_id = result["originating_object_pdf"]

    view_file_url = f"{NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={originating_object_id}"
    originating_object_pdf_url = f"{WEB_API_URL}download/{pdf_object_id}?name=result.pdf&action=view"

    pdf_html = (
        f"""
<a href="{originating_object_pdf_url}">PDF Link</a>
"""
        if pdf_object_id
        else None
    )

    return (
        f"""
    <div style="font-size:120%;">
        <a href="{view_file_url}">
            {originating_object_path}
        </a>
    </div>
    <div style="font-size:95%;">
        <div style="color:grey;font-size:95%;">
            Score: {score}
            &nbsp;
            {f"Source: {source}" if source else ""}
            {pdf_html}
        </div>
        <pre>""",
        text,
        """</pre>
    </div>
    """,
    )
