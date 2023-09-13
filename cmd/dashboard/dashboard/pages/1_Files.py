# Standard Libraries
import datetime
import ntpath
import os
import re
import urllib.parse
from typing import List

# 3rd Party Libraries
import extra_streamlit_components as stx
import streamlit as st
import templates
import utils
from streamlit_cookies_manager import CookieManager
from streamlit_elements import dashboard, elements, html, lazy, mui, sync
from streamlit_searchbox import st_searchbox
from streamlit_toggle import st_toggle_switch

POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or "1000"
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER").rstrip("/")
PAGE_SIZE = 8


global sources, projects
sources = []
projects = []

current_user = utils.header()

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


if st.session_state["authentication_status"]:
    cookies = CookieManager()
    if not cookies.ready():
        st.stop()

    triage_pattern = re.compile(r"^triage_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})_(?P<triage_value>.*)")
    notes_pattern = re.compile(r"^file_notes_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})$")

    for state in st.session_state:
        triage_matches = triage_pattern.search(state)
        if triage_matches:
            db_id = triage_matches.group("db_id").replace("_", "-")
            triage_value = triage_matches.group("triage_value")
            utils.update_triage_table(db_id, "file_data_enriched", current_user, triage_value)
            del st.session_state[state]
        else:
            notes_matches = notes_pattern.search(state)
            if notes_matches:
                db_id = notes_matches.group("db_id").replace("_", "-")
                utils.update_notes_table(db_id, "file_data_enriched", current_user, st.session_state[state].target.value)
                del st.session_state[state]

    utils.local_css("./css/files_style.css")

    set_search_params = {}
    para = st.experimental_get_query_params()

    for key in para.keys():
        match key:
            case "file_download_page":
                st.session_state.file_download_page = int(para["file_download_page"][0])
            case "file_show_triaged":
                st.session_state.file_show_triaged = bool(para["file_show_triaged"][0])
                set_search_params["file_show_triaged"] = st.session_state.file_show_triaged
            case "file_show_archive_originated":
                st.session_state.file_show_archive_originated = bool(para["file_show_archive_originated"][0])
                set_search_params["file_show_archive_originated"] = st.session_state.file_show_archive_originated
            case "file_path_pattern":
                st.session_state.file_path_pattern = para["file_path_pattern"][0]
                set_search_params["file_path_pattern"] = st.session_state.file_path_pattern
            case "file_notes_pattern":
                st.session_state.file_notes_pattern = para["file_notes_pattern"][0]
                set_search_params["file_notes_pattern"] = st.session_state.file_notes_pattern
            case "file_source_selection":
                st.session_state.file_source_selection = para["file_source_selection"][0]
                set_search_params["file_source_selection"] = st.session_state.file_source_selection
            case "file_project_selection":
                st.session_state.file_project_selection = para["file_project_selection"][0]
                set_search_params["file_project_selection"] = st.session_state.file_project_selection
            case "file_filter_tags":
                st.session_state.file_filter_tags = para["file_filter_tags"][0].split(",")
                set_search_params["file_filter_tags"] = st.session_state.file_filter_tags
            case "file_hash":
                st.session_state.file_hash = para["file_hash"][0]
                set_search_params["file_hash"] = st.session_state.file_hash
            case "file_order_desc_timestamp":
                st.session_state.file_order_desc_timestamp = para["file_order_desc_timestamp"][0]
                set_search_params["file_order_desc_timestamp"] = st.session_state.file_order_desc_timestamp

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

    # TODO: start/end times

    with st.expander("About Files"):
        st.markdown(
            """
        This page shows downloaded files processed by Nemesis, searchable by a
        variety of filters.

        The `Upload File` tab allows you to upload one or more files to Nemesis
        for processing (currently not functioning).
        """
        )

    chosen_tab = stx.tab_bar(
        data=[
            stx.TabBarItemData(id="downloaded_files", title="Downloaded Files", description="Downloaded Files Processed by Nemesis"),
            stx.TabBarItemData(id="upload_file", title="Upload File", description="Manually Upload a File to Nemesis for Processing"),
        ],
        default="downloaded_files",
    )

    if chosen_tab == "downloaded_files":
        if not st.session_state.file_download_page:
            st.session_state.file_download_page = 1

        # get all of the unique source names
        sources = utils.get_unique_sources("file_data_enriched")
        projects = utils.get_unique_projects("file_data_enriched")
        selected_tags = []
        source_selection = "%"
        project_selection = "%"
        file_hash = ""
        path_pattern = ""
        notes_pattern = ""
        show_triaged = False
        start_date = None
        start_time = None
        end_date = None
        end_time = None
        order_desc_timestamp = False

        if not sources or len(sources) == 0:
            st.error("No downloaded file data in the database")
        else:
            with st.expander("Search Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    path_pattern = st.text_input(
                        "The file path to search for, wildcards (*) supported, case insensitive",
                        placeholder="pdf, *pass*, *users*.exe, *.doc",
                        value=st.session_state.file_path_pattern
                    )
                    if path_pattern:
                        # Add wildcards if there aren't any
                        if "*" not in path_pattern and "%" not in path_pattern:
                            path_pattern = f"*{path_pattern}*"
                        path_pattern = path_pattern.replace("*", "%")
                    st.session_state.file_path_pattern = path_pattern
                    set_search_params["file_path_pattern"] = path_pattern
                with col2:
                    notes_pattern = st.text_input(
                        "Notes value to search for",
                        value=st.session_state.file_notes_pattern
                    )
                    st.session_state.file_notes_pattern = notes_pattern
                    set_search_params["file_notes_pattern"] = notes_pattern
                col1, col2 = st.columns(2)
                with col1:
                    source_selection = st_searchbox(
                        search_sources,
                        label="Enter a source/computer name to search for:",
                        placeholder="Begin typing name to search...",
                        key="file_searchbox_sources",
                        value=st.session_state.file_source_selection
                    )
                    st.session_state.file_source_selection = source_selection
                    set_search_params["file_source_selection"] = source_selection
                with col2:
                    project_selection = st_searchbox(
                        search_projects,
                        label="Enter a project name to filter for:",
                        placeholder="Type to search...",
                        key="file_searchbox_projects",
                        value=st.session_state.file_project_selection
                    )
                    st.session_state.file_project_selection = project_selection
                    set_search_params["file_project_selection"] = project_selection

                col1, col2 = st.columns(2)
                with col1:
                    selected_tags = st.multiselect(
                        label="Select a tag to filter for",
                        options=filter_tags,
                        default=st.session_state.file_filter_tags)
                    st.session_state.file_filter_tags = selected_tags
                    set_search_params["file_filter_tags"] = ",".join(selected_tags)
                with col2:
                    file_hash = st.text_input(
                        "The hash of a file to search for (optional)",
                        placeholder="MD5/SHA1/SHA256 hash value",
                        value=st.session_state.file_hash)
                    st.session_state.file_hash = file_hash
                    set_search_params["file_hash"] = file_hash

                col1, col2, col3 = st.columns(3)
                with col1:
                    subcol1, subcol2 = st.columns(2)
                    with subcol1:
                        start_date = st.date_input("Filter date (UTC) start", datetime.datetime.now() - datetime.timedelta(days=7))
                    with subcol2:
                        start_time = st.time_input("Filter time (UTC) start", datetime.time(0, 0))
                with col2:
                    subcol1, subcol2 = st.columns(2)
                    with subcol1:
                        end_date = st.date_input("Filter end date (UTC)", datetime.datetime.now())
                    with subcol2:
                        end_time = st.time_input("Filter end time (UTC)", datetime.datetime.now())
                with col3:
                    show_triaged = st_toggle_switch(
                        label="Show aready triaged files",
                        key="show_triaged_files",
                        default_value=st.session_state.file_show_triaged,
                        label_after=False,
                    )
                    st.session_state.file_show_triaged = show_triaged
                    set_search_params["file_show_triaged"] = show_triaged

                    show_archive_originated = st_toggle_switch(
                        label="Show files extracted from archives",
                        key="show_archive_originated",
                        default_value=st.session_state.file_show_archive_originated,
                        label_after=False,
                    )
                    st.session_state.file_show_archive_originated = show_archive_originated
                    set_search_params["file_show_archive_originated"] = show_archive_originated

                    order_desc_timestamp = st_toggle_switch(
                        label="Show newest files first",
                        key="order_desc_timestamp",
                        default_value=st.session_state.file_order_desc_timestamp,
                        label_after=False,
                    )
                    st.session_state.file_order_desc_timestamp = order_desc_timestamp
                    set_search_params["file_order_desc_timestamp"] = order_desc_timestamp

            # combing our start/end date/times
            start_datetime = datetime.datetime.combine(start_date, start_time)
            end_datetime = datetime.datetime.combine(end_date, end_time)

            # calculate the interval start for pagination
            from_i = (st.session_state.file_download_page - 1) * PAGE_SIZE

            if not source_selection:
                source_selection = "%"
            if not project_selection:
                project_selection = "%"

            # get the result count and dataframe for our search through postgres
            (total_hits, df) = utils.postgres_file_search(
                start=start_datetime,
                end=end_datetime,
                from_i=from_i,
                size=PAGE_SIZE,
                source=source_selection,
                project_id=project_selection,
                file_hash=file_hash,
                path_pattern=path_pattern,
                notes_pattern=notes_pattern,
                tags=selected_tags,
                show_triaged=show_triaged,
                show_archive_originated=show_archive_originated,
                order_desc_timestamp=order_desc_timestamp,
            )

            # number of results returned for this search
            num_results = len(df)

            # total_hits is the _total_ number of (non-paginated) results
            st.write(templates.number_of_results(total_hits), unsafe_allow_html=True)

            # pagination, if needed
            if total_hits > PAGE_SIZE:
                total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
                pagination_html = templates.file_pagination(total_pages, st.session_state.file_download_page, search_params=set_search_params)
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

                card_id_db_id_mapping = {}

                with elements("dashboard"):
                    with dashboard.Grid(layout=layout):
                        for index, file in df.iterrows():
                            object_id = file["object_id"]

                            # replace - with _ since streamlit doesn't support -'s in session state
                            unique_db_id = file["unique_db_id"].replace("-", "_")

                            dashboard_link = f"{NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={object_id}"

                            url_enc_file_name = urllib.parse.quote(file["name"])

                            base_file_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={url_enc_file_name}"
                            download_url = f"{base_file_url}&action=download"
                            view_download_url = f"{base_file_url}&action=view"
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
                                        with mui.Tooltip(title="View file details in Nemesis"):
                                            with html.span:
                                                mui.IconButton(mui.icon.Search, href=dashboard_link, target="_blank")
                                        with mui.Tooltip(title="View the file in browser"):
                                            with html.span:
                                                mui.IconButton(mui.icon.TextSnippet, href=view_download_url, target="_blank")
                                        if pdf_download_url:
                                            with mui.Tooltip(title="View the file as PDF"):
                                                with html.span:
                                                    mui.IconButton(mui.icon.PictureAsPdf, href=pdf_download_url, target="_blank")
                                        if extracted_source_download_url:
                                            with mui.Tooltip(title="View the extracted source code"):
                                                with html.span:
                                                    mui.IconButton(mui.icon.Code, href=extracted_source_download_url, target="_blank")

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
                                with mui.CardContent(sx={"flex": 1}):
                                    with mui.TableContainer(sx={"maxHeight": 200}):
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
                                                    if file['source']:
                                                        mui.TableCell("Source / Timestamp", size="small", sx=identifier_style)
                                                        mui.TableCell(f"{file['source']} @ {file['timestamp']}", size="small")
                                                    else:
                                                        mui.TableCell("Timestamp", size="small", sx=identifier_style)
                                                        mui.TableCell(f"{file['timestamp']}", size="small")
                                                with mui.TableRow(hover=True, padding="none"):
                                                    mui.TableCell("Size", sx=identifier_style)
                                                    mui.TableCell(file["size"])
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
                    pagination_html = templates.file_pagination(total_pages, st.session_state.file_download_page, search_params=set_search_params)
                    st.write(pagination_html, unsafe_allow_html=True)

    elif chosen_tab == "upload_file":
        cols = st.columns(4)
        with cols[0]:
            default_project = cookies["nemesus_project"] if "nemesus_project" in cookies else ""
            nemesus_project = st.text_input("The name of the current project", value=default_project, placeholder="Please enter a project name")
            if nemesus_project:
                cookies["nemesus_project"] = nemesus_project.upper()
        with cols[1]:
            default_operator = cookies["nemesis_operator"] if "nemesis_operator" in cookies else ""
            nemesis_operator = st.text_input("The name of the current operator", value=default_operator, placeholder="Please enter an operator name")
            if nemesis_operator:
                cookies["nemesis_operator"] = nemesis_operator.upper()
        with cols[2]:
            default_source = cookies["nemesis_source"] if "nemesis_source" in cookies else ""
            nemesis_source = st.text_input("The name of the source machine", value=default_source, placeholder="Please enter a source")
            if nemesis_source:
                cookies["nemesis_source"] = nemesis_source.upper()
        with cols[3]:
            default_expiration_days = cookies["nemesis_expiration_days"] if "nemesis_expiration_days" in cookies else "100"
            nemesis_expiration_days = st.text_input("Days until the data should expire", value=default_expiration_days)
            if nemesis_expiration_days:
                if nemesis_expiration_days.isdigit():
                    cookies["nemesis_expiration_days"] = nemesis_expiration_days

                else:
                    st.warning("Expiration days must be an integer!")

        original_file_path = st.text_input("Original file path (optional, used for masterkeys, Chromium data, etc.)")
        if original_file_path:
            original_file_path = original_file_path.replace("\\", "/")

        cookies.save()

        if (
            "nemesus_project" in cookies and cookies["nemesus_project"] != ""
            and "nemesis_operator" in cookies and cookies["nemesis_operator"] != ""
            and "nemesis_source" in cookies and cookies["nemesis_source"] != ""
            and "nemesis_expiration_days" in cookies and cookies["nemesis_expiration_days"] != ""
        ):

            uploaded_files = st.file_uploader("Choose a file for Nemesis to process", accept_multiple_files=True)

            for uploaded_file in uploaded_files:
                proceed = True
                file_name = ntpath.basename(uploaded_file.name)

                if original_file_path:
                    if original_file_path.lower().endswith(file_name.lower()):
                        file_path = original_file_path
                    elif original_file_path.endswith("/"):
                        file_path = f"{original_file_path}{file_name}"
                    else:
                        file_path = f"{original_file_path}/{file_name}"
                else:
                    file_path = uploaded_file.name

                # if the file is a Chromium based file, a proper path is needed
                if re.match("^(Local State|History|Login Data|Cookies)$", file_name, re.IGNORECASE):
                    if not utils.is_valid_chromium_file_path(file_path):
                        proceed = False
                        st.warning("Chromium data (Local State, History, Login Data, Cookies) needs a valid originating path!")

                if proceed:
                    bytes_data = uploaded_file.read()

                    nemesis_file_id = utils.nemesis_post_file(bytes_data)

                    if nemesis_file_id:
                        submission_time = datetime.datetime.utcnow()
                        expiration = submission_time + datetime.timedelta(days=int(cookies["nemesis_expiration_days"]))
                        submission_time_s = submission_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        expiration_s = expiration.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        metadata = {
                            "agent_id": cookies["nemesis_operator"],
                            "agent_type": "dashboard",
                            "automated": False,
                            "data_type": "file_data",
                            "expiration": expiration_s,
                            "source": cookies["nemesis_source"],
                            "project": cookies["nemesus_project"],
                            "timestamp": submission_time_s,
                        }

                        file_data = {"path": f"{file_path}", "size": len(bytes_data), "object_id": nemesis_file_id}

                        submission_id = utils.nemesis_post_data({"metadata": metadata, "data": [file_data]})

                        if submission_id:
                            st.success("Successful Nemesis submission", icon="✅")
                            nemesis_upload = f"""
        | Property            | Value |
        | ------------------- | ----------- |
        | __Submission ID__   | {submission_id} |
        | __Nemesis File ID__ | {nemesis_file_id} |
        | __Project__         | {cookies["nemesus_project"]} |
        | __Source__          | {cookies["nemesis_source"]} |
        | __Agent ID__        | {cookies["nemesis_operator"]} |
        | __Agent Type__      | dashboard |
        | __Automated__       | False |
        | __Data Type__       | file_data |
        | __Timestamp__       | {submission_time_s} |
        | __Expiration__      | {expiration_s} |
        | __Filename__        | {uploaded_file.name} |
        | __Size__            | {len(bytes_data)} |
                        """
                            st.markdown(nemesis_upload)
