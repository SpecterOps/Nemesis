# Standard Libraries
import datetime
import os
import re
import urllib.parse
from typing import List

# 3rd Party Libraries
import extra_streamlit_components as stx
import humanize
import streamlit as st
import templates
import utils
from streamlit_elements import dashboard, elements, html, lazy, mui, sync
from streamlit_searchbox import st_searchbox
from streamlit_toggle import st_toggle_switch

POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or "1000"
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER").rstrip("/")
PAGE_SIZE = 8


global sources, projects
sources = utils.get_unique_sources("file_data_enriched")
projects = utils.get_unique_projects("file_data_enriched")


# should be defined in ./packages/python/nemesiscommon/nemesiscommon/contents.py - E_TAG_*
filter_tags = [
    "contains_dpapi",
    "noseyparker_results",
    "parsed_creds",
    "encrypted",
    "deserialization",
    "cmd_execution",
    "remoting",
    "yara_matches",
    "file_canary",
]


def search_sources(search_term: str) -> List[str]:
    global sources
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), sources))


def search_projects(search_term: str) -> List[str]:
    global projects
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), projects))


def get_search_filters_from_session():
    search_filters = {}
    para = st.query_params

    for key in para.keys():
        match key:
            case "file_download_page":
                st.session_state.file_download_page = int(para["file_download_page"])
            case "file_show_triaged":
                st.session_state.file_show_triaged = bool(para["file_show_triaged"])
                search_filters["file_show_triaged"] = st.session_state.file_show_triaged
            case "file_show_archive_originated":
                st.session_state.file_show_archive_originated = bool(para["file_show_archive_originated"])
                search_filters["file_show_archive_originated"] = st.session_state.file_show_archive_originated
            case "file_path_pattern":
                st.session_state.file_path_pattern = para["file_path_pattern"]
                search_filters["file_path_pattern"] = st.session_state.file_path_pattern
            case "file_notes_pattern":
                st.session_state.file_notes_pattern = para["file_notes_pattern"]
                search_filters["file_notes_pattern"] = st.session_state.file_notes_pattern
            case "file_source_selection":
                st.session_state.file_source_selection = para["file_source_selection"]
                search_filters["file_source_selection"] = st.session_state.file_source_selection
            case "file_project_selection":
                st.session_state.file_project_selection = para["file_project_selection"]
                search_filters["file_project_selection"] = st.session_state.file_project_selection
            case "file_filter_tags":
                st.session_state.file_filter_tags = para["file_filter_tags"]
                search_filters["file_filter_tags"] = st.session_state.file_filter_tags
            case "file_hash":
                st.session_state.file_hash = para["file_hash"]
                search_filters["file_hash"] = st.session_state.file_hash
            case "file_order_desc_timestamp":
                st.session_state.file_order_desc_timestamp = para["file_order_desc_timestamp"]
                search_filters["file_order_desc_timestamp"] = st.session_state.file_order_desc_timestamp

    return search_filters


def build_and_get_search_filters():
    search_filters = get_search_filters_from_session()

    # After getting the search filters from the session, update them with any new user input
    with st.expander("Search Filters"):
        # Path and Notes filters
        col1, col2 = st.columns(2)
        with col1:
            path_pattern = st.text_input(
                "The file path to search for, wildcards (*) supported, case insensitive",
                placeholder="pdf, *pass*, *users*.exe, *.doc",
                value=st.session_state.file_path_pattern.replace("%", "*"),
            )
            if path_pattern:
                # Add wildcards if there aren't any
                if "*" not in path_pattern and "%" not in path_pattern:
                    path_pattern = f"*{path_pattern}*"
                path_pattern = path_pattern.replace("*", "%")
            st.session_state.file_path_pattern = path_pattern
            search_filters["file_path_pattern"] = path_pattern
        with col2:
            notes_pattern = st.text_input("Notes value to search for", value=st.session_state.file_notes_pattern)
            st.session_state.file_notes_pattern = notes_pattern
            search_filters["file_notes_pattern"] = notes_pattern

        # Source(Computer name) and Project filters
        col1, col2 = st.columns(2)
        with col1:
            file_source_selection = st_searchbox(
                search_sources,
                label="Enter a source/computer name to search for:",
                placeholder="Begin typing name to search...",
                key="file_searchbox_sources",
                value=st.session_state.file_source_selection,
            )
            st.session_state.file_source_selection = file_source_selection
            search_filters["file_source_selection"] = file_source_selection
        with col2:
            file_project_selection = st_searchbox(
                search_projects,
                label="Enter a project name to filter for:",
                placeholder="Type to search...",
                key="file_searchbox_projects",
                value=st.session_state.file_project_selection,
            )
            st.session_state.file_project_selection = file_project_selection
            search_filters["file_project_selection"] = file_project_selection

        # Tag and hash filters
        col1, col2 = st.columns(2)
        with col1:
            file_filter_tags = st.multiselect(
                label="Select a tag to filter for",
                options=filter_tags,
                default=st.session_state.file_filter_tags,
            )
            st.session_state.file_filter_tags = file_filter_tags
            search_filters["file_filter_tags"] = file_filter_tags

        with col2:
            file_hash = st.text_input(
                "The hash of a file to search for (optional)",
                placeholder="MD5/SHA1/SHA256 hash value",
                value=st.session_state.file_hash,
            )
            st.session_state.file_hash = file_hash
            search_filters["file_hash"] = file_hash

        # Date and Toggle filters
        col1, col2, col3 = st.columns(3)
        with col1:
            subcol1, subcol2 = st.columns(2)
            with subcol1:
                start_date = st.date_input("Filter date (UTC) start", datetime.datetime.now() - datetime.timedelta(days=90))
            with subcol2:
                start_time = st.time_input("Filter time (UTC) start", datetime.time(0, 0))
        with col2:
            subcol1, subcol2 = st.columns(2)
            with subcol1:
                end_date = st.date_input("Filter end date (UTC)", datetime.datetime.now() + datetime.timedelta(days=1))
            with subcol2:
                end_time = st.time_input("Filter end time (UTC)", datetime.datetime.now())

        start_datetime = datetime.datetime.combine(start_date, start_time)
        end_datetime = datetime.datetime.combine(end_date, end_time)

        st.session_state.start_datetime = start_datetime
        search_filters["start_datetime"] = start_datetime
        st.session_state.end_datetime = end_datetime
        search_filters["end_datetime"] = end_datetime

        with col3:
            show_triaged = st_toggle_switch(
                label="Show aready triaged files",
                key="show_triaged_files",
                default_value=st.session_state.file_show_triaged,
                label_after=False,
            )
            st.session_state.file_show_triaged = show_triaged
            search_filters["file_show_triaged"] = show_triaged

            show_archive_originated = st_toggle_switch(
                label="Show files extracted from archives",
                key="show_archive_originated",
                default_value=st.session_state.file_show_archive_originated,
                label_after=False,
            )
            st.session_state.file_show_archive_originated = show_archive_originated
            search_filters["file_show_archive_originated"] = show_archive_originated

            order_desc_timestamp = st_toggle_switch(
                label="Show newest files first",
                key="order_desc_timestamp",
                default_value=st.session_state.file_order_desc_timestamp,
                label_after=False,
            )
            st.session_state.file_order_desc_timestamp = order_desc_timestamp
            search_filters["file_order_desc_timestamp"] = order_desc_timestamp

    return search_filters


def build_file_listing():
    if not st.session_state.file_download_page:
        st.session_state.file_download_page = 1

    if not sources or len(sources) == 0:
        st.error("No downloaded file data in the database")
        return

    search_filters = build_and_get_search_filters()

    # calculate the interval start for pagination
    from_i = (st.session_state.file_download_page - 1) * PAGE_SIZE

    # get the result count and dataframe for our search through postgres
    (total_hits, df) = utils.postgres_file_search(
        startdate=search_filters["start_datetime"],
        enddate=search_filters["end_datetime"],
        from_i=from_i,
        size=PAGE_SIZE,
        source=search_filters["file_source_selection"] if search_filters["file_source_selection"] else "%",
        project_id=search_filters["file_project_selection"] if search_filters["file_project_selection"] else "%",
        file_hash=search_filters["file_hash"],
        path_pattern=search_filters["file_path_pattern"],
        notes_pattern=search_filters["file_notes_pattern"],
        tags=search_filters["file_filter_tags"] if search_filters["file_filter_tags"] else [],
        show_triaged=search_filters["file_show_triaged"] if search_filters["file_show_triaged"] else False,
        show_archive_originated=search_filters["file_show_archive_originated"],
        order_desc_timestamp=search_filters["file_order_desc_timestamp"] if search_filters["file_order_desc_timestamp"] else False,
    )

    # number of results returned for this search
    num_results = len(df)

    # total_hits is the _total_ number of (non-paginated) results
    st.write(templates.number_of_results(total_hits), unsafe_allow_html=True)

    # pagination, if needed
    if total_hits > PAGE_SIZE:
        total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
        pagination_html = templates.file_pagination(total_pages, st.session_state.file_download_page, search_params=search_filters)
        st.write(pagination_html, unsafe_allow_html=True)

    if num_results > 0:
        layout = [
            # Grid layout parameters: element_identifier, x_pos, y_pos, width, height, [item properties...]
            dashboard.Item("1", 0, 0, 10, 2.5, isDraggable=False, isResizable=False, sx={"height": "100%"}),
            dashboard.Item("2", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("3", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("4", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("5", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("6", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("7", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
            dashboard.Item("8", 0, 0, 10, 2.5, isDraggable=False, isResizable=False),
        ]

        with elements("dashboard"):
            with dashboard.Grid(layout=layout):
                for index, file in df.iterrows():
                    object_id = file["object_id"]

                    # replace - with _ since streamlit doesn't support -'s in session state
                    unique_db_id = file["unique_db_id"].replace("-", "_")

                    dashboard_link = f"{NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={object_id}"

                    url_enc_file_name = urllib.parse.quote(file["name"])

                    base_file_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={url_enc_file_name}"
                    view_download_url = f"{base_file_url}&action=view"
                    view_raw_url = f"{base_file_url}&action=view_raw"
                    pdf_download_url = ""
                    extracted_source_download_url = ""

                    # if we don't have default values, built the appropriate download URIs
                    if file["converted_pdf_id"] != "00000000-0000-0000-0000-000000000000":
                        pdf_download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{file['converted_pdf_id']}?name={url_enc_file_name}.pdf&action=view"
                    if file["extracted_source_id"] != "00000000-0000-0000-0000-000000000000":
                        extracted_source_download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{file['extracted_source_id']}?name={url_enc_file_name}.zip&action=download"

                    # If the file is a PDF, set the PDF URL
                    if file["name"].endswith(".pdf"):
                        pdf_download_url = view_download_url

                    with mui.Card(
                        key=f"{1*index+1}",
                        sx={
                            "display": "flex",
                            "flexDirection": "column",
                            "borderRadius": 2,
                            "overflow": "auto",
                            "overflowY": "auto",
                            "m": "10",
                            "gap": "10px",
                        },
                        padding=1,
                        elevation=1,
                        spacing=10,
                    ):
                        with mui.AppBar(position="sticky", variant="h7", sx={"minHeight": 32}):
                            with mui.Toolbar(variant="dense", sx={"minHeight": 48, "height": 48}):
                                mui.Typography(file["name"])
                                with mui.Tooltip(title="Download the file"):
                                    with html.span:
                                        mui.IconButton(mui.icon.Download, href=base_file_url)
                                with mui.Tooltip(title="View the raw file as plaintext in the browser"):
                                    with html.span:
                                        mui.IconButton(mui.icon.RawOn, href=view_raw_url, target="_blank")
                                if pdf_download_url:
                                    with mui.Tooltip(title="View the file as PDF"):
                                        with html.span:
                                            mui.IconButton(mui.icon.PictureAsPdf, href=pdf_download_url, target="_blank")
                                if extracted_source_download_url:
                                    with mui.Tooltip(title="View the extracted source code"):
                                        with html.span:
                                            mui.IconButton(mui.icon.Code, href=extracted_source_download_url, target="_blank")
                                with mui.Tooltip(title="Detailed file information"):
                                    with html.span:
                                        mui.IconButton(mui.icon.Info, href=dashboard_link, target="_blank")

                                mui.Box(sx={"flexGrow": 1})

                                thumbs_up_color = "default"
                                thumbs_down_color = "default"
                                question_color = "default"
                                match file["triage"]:
                                    case "useful":
                                        thumbs_up_color = "success"
                                    case "notuseful":
                                        thumbs_down_color = "error"
                                    case "unknown":
                                        question_color = "warning"

                                with html.span:
                                    mui.Typography("Triage")
                                with mui.Tooltip(title="Mark file as useful"):
                                    with html.span:
                                        mui.IconButton(mui.icon.ThumbUpOffAlt, color=thumbs_up_color, onClick=sync(f"triage_{unique_db_id}_useful"))
                                with mui.Tooltip(title="Mark file as not useful"):
                                    with html.span:
                                        mui.IconButton(mui.icon.ThumbDownOffAlt, color=thumbs_down_color, onClick=sync(f"triage_{unique_db_id}_notuseful"))
                                with mui.Tooltip(title="Mark file as needing additional investigation"):
                                    with html.span:
                                        mui.IconButton(mui.icon.QuestionMark, color=question_color, onClick=sync(f"triage_{unique_db_id}_unknown"))

                        # Information table
                        with mui.CardContent(sx={"flex": 1, "overflow": "hidden"}):
                            with mui.TableContainer(sx={"maxHeight": 250, "overflow": "hidden"}):
                                with mui.Table(size="small", overflowX="hidden", whiteSpace="nowrap"):
                                    with mui.TableBody():
                                        identifier_style = {
                                            "fontWeight": "bold",
                                            "borderRight": "1px solid",
                                            "whiteSpace": "nowrap",
                                            "padding": "0px 5px 0px 0px",
                                        }

                                        with mui.TableRow(hover=True, padding="none"):
                                            mui.TableCell("Path", size="small", sx=identifier_style)
                                            mui.TableCell(file["path"], width="100%")
                                        with mui.TableRow(hover=True, padding="none"):
                                            if file["source"]:
                                                mui.TableCell("Source / Timestamp", size="small", sx=identifier_style)
                                                mui.TableCell(f"{file['source']} @ {file['timestamp']}", size="small")
                                            else:
                                                mui.TableCell("Timestamp", size="small", sx=identifier_style)
                                                mui.TableCell(f"{file['timestamp']}", size="small")
                                        with mui.TableRow(hover=True, padding="none"):
                                            mui.TableCell("Size", sx=identifier_style)
                                            mui.TableCell(humanize.naturalsize(file["size"]))
                                        with mui.TableRow(hover=True, padding="none"):
                                            mui.TableCell("SHA1 hash", sx=identifier_style)
                                            mui.TableCell(file["sha1"])
                                        with mui.TableRow(hover=True, padding="none"):
                                            mui.TableCell("Magic Type", sx=identifier_style)
                                            mui.TableCell(file["magic_type"])
                                        if file["tags"]:
                                            with mui.TableRow(hover=True, padding="none"):
                                                mui.TableCell("Tags", sx=identifier_style)
                                                with mui.TableCell():
                                                    # Tags
                                                    for tag in file["tags"]:
                                                        link_uri = ""
                                                        if tag == "parsed_creds":
                                                            link_uri = f"{NEMESIS_HTTP_SERVER}/dashboard/Credentials?object_id={object_id}"
                                                        elif tag == "noseyparker_results":
                                                            link_uri = f"{NEMESIS_HTTP_SERVER}/dashboard/NoseyParker"
                                                        if link_uri:
                                                            mui.Chip(   label=tag,
                                                                        href=link_uri,
                                                                        component="a",
                                                                        target="_blank",
                                                                        clickable=True,
                                                                        color="info")
                                                        else:
                                                            mui.Chip(label=tag, color="primary")
                            # Notes
                            mui.Typography("Comments:")
                            with mui.Box(sx={"flexGrow": 1}):
                                end = mui.IconButton(mui.icon.Save, onClick=sync())

                                mui.TextField(
                                    # label="Input Any Notes Here",
                                    key=f"file_notes_{unique_db_id}",
                                    defaultValue=file["notes"],
                                    variant="outlined",
                                    margin="none",
                                    multiline=True,
                                    onChange=lazy(sync(f"file_notes_{unique_db_id}")),
                                    fullWidth=True,
                                    sx={"flexGrow": 1},
                                    InputProps={"endAdornment": end},
                                )

                # draw in nearly invisible placeholders for the rest of the PAGE_SIZE
                #   this is because the grid can't be redrawn, so if the layout isn't filled
                #   in on first render, only the the X first grid slots (where X = original number of rendered entries)
                #   will be rendered
                for i in range(len(df) + 1, PAGE_SIZE + 1):
                    mui.Box(
                        "",
                        key=i,
                        sx={
                            "maxHeight": 1,
                            "maxWidth": 1,
                        },
                    )

        # pagination, if needed
        if total_hits > PAGE_SIZE:
            total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
            pagination_html = templates.file_pagination(total_pages, st.session_state.file_download_page, search_params=search_filters)
            st.write(pagination_html, unsafe_allow_html=True)


def init_session_state():
    if "file_download_page" not in st.session_state:
        st.session_state.file_download_page = None
    if "file_show_triaged" not in st.session_state:
        st.session_state.file_show_triaged = False
    if "file_show_archive_originated" not in st.session_state:
        st.session_state.file_show_archive_originated = False
    if "file_path_pattern" not in st.session_state:
        st.session_state.file_path_pattern = ""
    if "file_notes_pattern" not in st.session_state:
        st.session_state.file_notes_pattern = ""
    if "file_source_selection" not in st.session_state:
        st.session_state.file_source_selection = ""
    if "file_project_selection" not in st.session_state:
        st.session_state.file_project_selection = ""
    if "file_filter_tags" not in st.session_state:
        st.session_state.file_filter_tags = []
    if "file_hash" not in st.session_state:
        st.session_state.file_hash = ""
    if "file_order_desc_timestamp" not in st.session_state:
        st.session_state.file_order_desc_timestamp = False


def build_about_expander():
    with st.expander("About Files"):
        st.markdown(
            """
        This page shows files processed by Nemesis. Files are searchable using variety of filters.

        Operators can triage files as "useful", "not useful", or "needs more investigation" by clicking the thumbs up, thumbs down, and question mark buttons in the top right of each file.
"""
        )


def build_page(username: str):
    triage_pattern = re.compile(r"^triage_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})_(?P<triage_value>.*)")
    notes_pattern = re.compile(r"^file_notes_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})$")

    for state in st.session_state:
        triage_matches = triage_pattern.search(state)
        if triage_matches:
            db_id = triage_matches.group("db_id").replace("_", "-")
            triage_value = triage_matches.group("triage_value")
            utils.update_triage_table(db_id, "file_data_enriched", username, triage_value)
            del st.session_state[state]
        else:
            notes_matches = notes_pattern.search(state)
            if notes_matches:
                db_id = notes_matches.group("db_id").replace("_", "-")
                utils.update_notes_table(db_id, "file_data_enriched", username, st.session_state[state].target.value)
                del st.session_state[state]

    utils.local_css("./css/files_style.css")
    init_session_state()
    build_about_expander()
    build_file_listing()


utils.render_nemesis_page(build_page)
