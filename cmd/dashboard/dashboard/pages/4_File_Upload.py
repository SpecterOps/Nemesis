# Standard Libraries
import datetime
import ntpath
import os
import re

# 3rd Party Libraries
import streamlit as st
import utils
from streamlit_cookies_manager import CookieManager

#NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")
NEMESIS_HTTP_SERVER = ""


def build_page(authenticate_user: str):
    cookies = CookieManager()
    if not cookies.ready():
        st.stop()

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
        "nemesus_project" in cookies
        and cookies["nemesus_project"] != ""
        and "nemesis_operator" in cookies
        and cookies["nemesis_operator"] != ""
        and "nemesis_source" in cookies
        and cookies["nemesis_source"] != ""
        and "nemesis_expiration_days" in cookies
        and cookies["nemesis_expiration_days"] != ""
    ):
        uploaded_files = st.file_uploader("Choose a file for Nemesis to process", accept_multiple_files=True)

        if not uploaded_files:
            return

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
        | __Nemesis File ID__ | [{nemesis_file_id}]({NEMESIS_HTTP_SERVER}/dashboard/File_Viewer?object_id={nemesis_file_id}) |
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
                        st.markdown(nemesis_upload, unsafe_allow_html=True)


utils.render_nemesis_page(build_page)
