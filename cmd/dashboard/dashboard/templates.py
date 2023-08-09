# Standard Libraries
import os
import urllib.parse
import re

# 3rd Party Libraries
import streamlit as st

# Adapted from https://github.com/chiachong/medium-search-app/blob/9fde32173731d4f696fdee05454314277504d89f/srcs/streamlit_app/templates.py


PUBLIC_KIBANA_URL = os.environ.get("PUBLIC_KIBANA_URL")
WEB_API_URL = os.environ.get("WEB_API_URL")
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")


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


def text_search_result(
    i: int, url: str, pdf_url: str, source: str, path: str, highlights: str, length: str, originating_object_id: str, **kwargs
) -> str:
    """HTML scripts to display text search results."""

    download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{originating_object_id}"

    return (f"""
        <div style="font-size:120%;">
            {i + 1}.
            <a href="{url}">
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
                &nbsp;&nbsp;
                <a href="{download_url}">
                    Download File
                </a>
            </div>
            <pre>""", highlights , """</pre>
        </div>
    """)


def sourcecode_search_result(
    i: int, elastic_url: str, download_url: str, source: str, path: str, name: str, language: str, highlights: str, size: str, **kwargs
) -> str:
    """HTML scripts to display text search results."""

    view_url = f"{download_url}?name={name}"

    return (f"""
        <div style="font-size:120%;">
            {i + 1}.
            <a href="{elastic_url}">
                {path}
            </a>
        </div>
        <div style="font-size:95%;">
            <div style="color:grey;font-size:95%;">
                <b>{language}</b>
                &nbsp;
                {size} bytes
                &nbsp;
                <a href="{view_url}&action=view">
                    View File
                </a>
                &nbsp;&nbsp;
                <a href="{view_url}">
                    Download File
                </a>
            </div>
            <pre>""", highlights , """</pre>
        </div>
    """)


def semantic_search_result(result) -> str:
    """HTML scripts to display a semantic search json result."""

    text = result["text"]
    score = result["score"]
    source = ""
    if "source" in result:
        source = result["source"]
    originating_object_id = result["originating_object_id"]
    download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{originating_object_id}"
    originating_object_path = result["originating_object_path"]
    pdf_object_id = result["originating_object_pdf"]
    originating_object_url = f"{PUBLIC_KIBANA_URL}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{originating_object_id}')))),index:'26360ae8-a518-4dac-b499-ef682d3f6bac')&_g=(time:(from:now-1y%2Fd,to:now))"
    originating_object_pdf_url = f"{WEB_API_URL}download/{pdf_object_id}?name=result.pdf&action=view"

    return (f"""
    <div style="font-size:120%;">
        <a href="{originating_object_url}">
            {originating_object_path}
        </a>
    </div>
    <div style="font-size:95%;">
        <div style="color:grey;font-size:95%;">
            Score: {score}
            &nbsp;
            <a href="{originating_object_pdf_url}">
                PDF Link
            </a>
            &nbsp;&nbsp;
            <a href="{download_url}">
                Download File
            </a>
        </div>
        <pre>""", text, """</pre>
    </div>
    """)


def default_file(base_result: dict) -> str:
    """Return HTML to display an default file."""

    nemesis_file_type = base_result["nemesisFileType"]
    path = base_result["path"]
    source = ""
    if "metadata" in base_result and "source" in base_result["metadata"]:
        source = base_result["metadata"]["source"]
    parsed_data = base_result["parsedData"]
    sha1 = base_result["hashes"]["sha1"]
    magic_type = base_result["magicType"]
    object_id = base_result["objectId"]

    kibana_base = os.environ.get("PUBLIC_KIBANA_URL") or ""
    kibana_url = (
        f"{kibana_base}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{object_id}')))))&_g=(time:(from:now-1y%%2Fd,to:now))"
    )
    download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}"

    st.write(
        f"""
        <div style="font-size:120%;">
            <a href="{kibana_url}">
                {path}
            </a>
        </div>
        <div style="font-size:100%;">
            <div style="color:grey;font-size:100%;">
                <b>Source</b>: {source}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Download File:</b>
                <a href="{download_url}">
                    download
                </a>
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Magic Type</b>: {magic_type}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Nemesis File Type</b>: {nemesis_file_type}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>SHA1</b>: {sha1}
            </div>
            <div style="color:grey;font-size:100%;">
            </div>
        </div>
    """,
        unsafe_allow_html=True,
    )

    if parsed_data:
        st.write("Parsed File Data:")
        st.json(parsed_data)


def office_document(base_result: dict) -> str:
    """Return HTML to display an office document."""

    nemesis_file_type = base_result["nemesisFileType"]
    path = base_result["path"]
    source = ""
    if "metadata" in base_result and "source" in base_result["metadata"]:
        source = base_result["metadata"]["source"]
    parsed_data = base_result["parsedData"]
    sha1 = base_result["hashes"]["sha1"]
    magic_type = base_result["magicType"]
    object_id = base_result["objectId"]
    pdf_url = base_result["convertedPdfURL"]

    kibana_base = os.environ.get("PUBLIC_KIBANA_URL") or ""
    kibana_url = (
        f"{kibana_base}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{object_id}')))))&_g=(time:(from:now-1y%%2Fd,to:now))"
    )
    download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}"

    st.write(
        f"""
        <div style="font-size:120%;">
            <a href="{kibana_url}">
                {path}
            </a>
        </div>
        <div style="font-size:100%;">
            <div style="color:grey;font-size:100%;">
                <b>Source</b>: {source}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Download File:</b>
                <a href="{download_url}">
                    download
                </a>
            </div>
            <div style="color:grey;font-size:100%;">
                View PDF:
                <a href="{pdf_url}">
                    view
                </a>
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Magic Type</b>: {magic_type}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>Nemesis File Type</b>: {nemesis_file_type}
            </div>
            <div style="color:grey;font-size:100%;">
                <b>SHA1</b>: {sha1}
            </div>
            <div style="color:grey;font-size:100%;">
            </div>
        </div>
    """,
        unsafe_allow_html=True,
    )

    if parsed_data:
        st.write("Parsed File Data:")
        st.json(parsed_data)
