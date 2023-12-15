# Standard Libraries
import os
import pathlib
import re
import urllib.parse
import uuid

# 3rd Party Libraries
import extra_streamlit_components as stx
import requests
import streamlit as st
import utils
from annotated_text import annotated_text, annotation
from streamlit_elements import (dashboard, editor, elements, html, lazy, mui,
                                sync)
from streamlit_toggle import st_toggle_switch

NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")

triage_pattern = re.compile(r"^triage_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})_(?P<triage_value>.*)")
notes_pattern = re.compile(r"^file_notes_(?P<db_id>[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})$")


def is_uuid(str_uuid: str):
    try:
        uuid.UUID(str_uuid)
        return True
    except:
        return False


def create_file_info_toolbar(object_id, file):
    url_enc_file_name = urllib.parse.quote(file["name"])

    view_raw_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?action=view_raw"
    download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={url_enc_file_name}&action=download"

    if "extracted_source_id" in file and file["extracted_source_id"] != "00000000-0000-0000-0000-000000000000":
        extracted_source_download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{file['extracted_source_id']}"
    else:
        extracted_source_download_url = None

    # Get PDF URL
    if "converted_pdf_id" in file and file["converted_pdf_id"] != "00000000-0000-0000-0000-000000000000":
        pdf_url = f"{NEMESIS_HTTP_SERVER}/api/download/{file['converted_pdf_id']}?action=view&name={url_enc_file_name}.pdf"
    elif file["name"].endswith(".pdf"):
        pdf_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={url_enc_file_name}&action=view"
    else:
        pdf_url = None

    kibana_link = f"{NEMESIS_HTTP_SERVER}/kibana/app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{object_id}')))),index:'26360ae8-a518-4dac-b499-ef682d3f6bac')&_g=(time:(from:now-1y%2Fd,to:now))"

    with mui.AppBar(position="sticky", variant="h7", sx={"minHeight": 32}):
        with mui.Toolbar(variant="dense", sx={"minHeight": 48, "height": 48}):
            mui.Typography(file["name"])
            with mui.Tooltip(title="Download the file"):
                with html.span:
                    mui.IconButton(mui.icon.Download, href=download_url)
            with mui.Tooltip(title="View the file in Kibana"):
                with html.span:
                    mui.IconButton(mui.icon.Search, href=kibana_link, target="_blank")
            with mui.Tooltip(title="View the raw file as plaintext in the browser"):
                with html.span:
                    mui.IconButton(mui.icon.RawOn, href=view_raw_url, target="_blank")
            if pdf_url:
                with mui.Tooltip(title="View the file as PDF"):
                    with html.span:
                        mui.IconButton(mui.icon.PictureAsPdf, href=pdf_url, target="_blank")

            if extracted_source_download_url:
                with mui.Tooltip(title="Download the extracted source code"):
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

            unique_db_id = file["unique_db_id"].replace("-", "_")

            with html.span:
                mui.Typography("Triage Action: ")
            with mui.Tooltip(title="Mark file as useful"):
                with html.span:
                    mui.IconButton(mui.icon.ThumbUpOffAlt, color=thumbs_up_color, onClick=sync(f"triage_{unique_db_id}_useful"))
            with mui.Tooltip(title="Mark file as not useful"):
                with html.span:
                    mui.IconButton(mui.icon.ThumbDownOffAlt, color=thumbs_down_color, onClick=sync(f"triage_{unique_db_id}_notuseful"))
            with mui.Tooltip(title="Mark file as needing additional investigation"):
                with html.span:
                    mui.IconButton(mui.icon.QuestionMark, color=question_color, onClick=sync(f"triage_{unique_db_id}_unknown"))


def create_file_info_table(file):
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
                        mui.TableCell(f"{file['size']}")
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
        unique_db_id = file["unique_db_id"].replace("-", "_")

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


def build_page(username: str):
    object_id = utils.get_single_valued_param("object_id")

    # Prompt for the object ID if there isn't one
    if not object_id:
        object_id = st.text_input("Enter file's unique identifier (UUID):")

    if not object_id:  # No URL param and nothing from text input
        return

    if not is_uuid(object_id):
        st.error(f"'{object_id}' is not a valid UUID", icon="🚨")
        return

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

    file = utils.get_file_information(object_id)

    if not ((file is None) or len(file) == 0):
        object_id = file["object_id"]
        extension = pathlib.Path(file["name"]).suffix.strip(".").lower()

        download_url_internal = f"http://enrichment-webapi:9910/download/{object_id}"

        tabs = [stx.TabBarItemData(id=1, title="Basic File Info", description="Basic File Information"), stx.TabBarItemData(id=3, title="Elasticsearch Info", description="Elasticsearch Information Dump")]

        es_results = utils.elastic_file_search(object_id)
        if es_results and es_results["hits"]["total"]["value"] == 1:
            if "noseyparker" in es_results["hits"]["hits"][0]["_source"]:
                tabs.append(stx.TabBarItemData(id=2, title="Noseyparker Results", description="Noseyparker Results"))

        chosen_tab = stx.tab_bar(
            data=tabs,
            default=1,
        )

        if chosen_tab == str(1):  # "basic_file_info":
            layout = [
                # Grid layout parameters: element_identifier, x_pos, y_pos, width, height, [item properties...]
                dashboard.Item("1", 0, 0, 10, 2.5, isDraggable=False, isResizable=False, sx={"height": "100%"}),
                dashboard.Item("2", 0, 0, 10, 5, isDraggable=False, isResizable=False, sx={"height": "100%"}),
            ]

            with elements("dashboard"):
                with dashboard.Grid(layout=layout):
                    with mui.Card(
                        key="1",
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
                        create_file_info_toolbar(object_id, file)
                        create_file_info_table(file)

                    if file["size"] > 20000000:
                        st.warning("File is over 20MB, not displaying in Monaco")
                    else:
                        response = requests.get(download_url_internal)
                        if response.status_code != 200:
                            st.error(f"Error retrieving text data from {download_url_internal}, status code: {response.status_code}", icon="🚨")
                        else:
                            # Monaco editor display for ascii files
                            with mui.Card(
                                key="2",
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
                                try:
                                    textcontent = response.content.decode(encoding="utf-8", errors="ignore")

                                    word_wrap = st_toggle_switch(
                                        label="Text Word Wrap",
                                        key="word_wrap",
                                        label_after=False,
                                    )

                                    editor.Monaco(height="64vh", options={"readOnly": True, "wordWrap": word_wrap}, defaultValue=textcontent, language=utils.map_extension_to_monaco_language(extension), theme="vs-dark")

                                except Exception as e:
                                    st.error(f"Error displaying file in Monaco editor: {e}", icon="🚨")

        elif chosen_tab == str(2):  # noseyparker_results
            if es_results != {}:
                total_hits = es_results["hits"]["total"]["value"]
                num_results = len(es_results["hits"]["hits"])
                if total_hits > 0:
                    for i in range(num_results):
                        object_id = es_results["hits"]["hits"][i]["_source"]["objectId"]
                        file_name = es_results["hits"]["hits"][i]["_source"]["name"]
                        download_url_internal = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={file_name}"

                        for ruleMatch in es_results["hits"]["hits"][i]["_source"]["noseyparker"]["ruleMatches"]:
                            for match in ruleMatch["matches"]:
                                if "matching" in match["snippet"]:
                                    rule_name = match["ruleName"]

                                    if "before" in match["snippet"]:
                                        before = match["snippet"]["before"].replace("\n\t", " ")
                                    else:
                                        before = ""

                                    matching = match["snippet"]["matching"]

                                    if "after" in match["snippet"]:
                                        after = match["snippet"]["after"].replace("\n\t", " ")
                                    else:
                                        after = ""

                                    st.subheader(f"Rule: {rule_name}", divider="red")
                                    st.write("Matching text:")
                                    st.code(matching)
                                    st.write("Context:")
                                    st.code(before + matching + after)
                                    st.divider()

        elif chosen_tab == str(3):  # "elasticsearch_info"
            if es_results != {}:
                total_hits = es_results["hits"]["total"]["value"]
                if total_hits == 0:
                    st.warning("No results found in Elasticsearch!")
                elif total_hits == 1:
                    st.subheader("Elasticsearch Data")
                    st.json(es_results["hits"]["hits"][0])
                else:
                    st.warning("Too many results found in Elasticsearch!")


utils.render_nemesis_page(build_page)
