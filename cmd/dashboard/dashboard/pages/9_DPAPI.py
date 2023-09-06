# Standard Libraries
import datetime
import logging
import os
import re
import time

# 3rd Party Libraries
import extra_streamlit_components as stx
import streamlit as st
import utils
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from streamlit_cookies_manager import CookieManager

PUBLIC_KIBANA_URL = os.environ.get("PUBLIC_KIBANA_URL") or ""
POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or "1000"
PAGE_SIZE = os.environ.get("PAGE_SIZE") or "10"
PAGE_SIZE = int(PAGE_SIZE)


####################################################
#
# Main app functionality
#
####################################################

current_user = utils.header()

# Get the Elasticsearch client
logging.getLogger("elasticsearch").setLevel(logging.ERROR)
es_client = utils.wait_for_elasticsearch()

# only execute the main functionality if the user is authenticated
if st.session_state["authentication_status"]:
    cookies = CookieManager()
    if not cookies.ready():
        st.stop()

    with st.expander("About DPAPI"):
        st.markdown(
            """
        This page shows the number of DPAPI user and system masterkeys and
        target DPAPI data that is decrypted/still encrypted. Additionally,
        plaintext masterkeys can be submitted. as well as DPAPI_SYSTEM keys
        to decrpyt system materkeys and domain backup keys to decrypt user
        domain masterkeys.
        """
        )

    query_params = st.experimental_get_query_params()

    # pull our specified tab from the query parameters, otherwise use "overview" as the default
    if "tab" not in query_params or not query_params["tab"]:
        query_params["tab"] = ["overview"]

    chosen_tab = stx.tab_bar(
        data=[
            stx.TabBarItemData(id="overview", title="DPAPI Overview", description="Overview of DPAPI Data"),
            stx.TabBarItemData(id="masterkeys", title="Masterkeys", description="DPAPI Masterkey Triage"),
        ],
        default=query_params["tab"][0],
    )
    query_params["tab"] = [chosen_tab]
    st.experimental_set_query_params(**query_params)

    if chosen_tab == "overview":
        cols = st.columns(4)
        with cols[0]:
            total_dpapi_blobs = utils.postgres_count_dpapi_blobs()
            dec_dpapi_blobs = utils.postgres_count_dpapi_blobs(show_all=False)
            st.metric("DPAPI Blobs", f"{dec_dpapi_blobs} / {total_dpapi_blobs}")
        with cols[1]:
            total_statefiles = utils.postgres_count_state_files()
            dec_statefiles = utils.postgres_count_state_files(show_all=False)
            st.metric("Chromium State Files", f"{dec_statefiles} / {total_statefiles}")
        with cols[2]:
            total_dpapi_backupkeys = utils.postgres_count_entries("dpapi_domain_backupkeys")
            st.metric("DPAPI Domain Backupkeys", total_dpapi_backupkeys)

        st.divider()
        cols = st.columns(4)
        with cols[0]:
            total_masterkeys = utils.postgres_count_masterkeys()
            dec_masterkeys = utils.postgres_count_masterkeys(show_all=False)
            st.metric("Total Masterkeys", f"{dec_masterkeys} / {total_masterkeys}")
        with cols[1]:
            domain_user_masterkeys = utils.postgres_count_masterkeys(key_type="domain_user")
            dec_domain_user_masterkeys = utils.postgres_count_masterkeys(show_all=False, key_type="domain_user")
            st.metric("Domain User Masterkeys", f"{dec_domain_user_masterkeys} / {domain_user_masterkeys}")
        with cols[2]:
            local_user_masterkeys = utils.postgres_count_masterkeys(key_type="local_user")
            dec_local_user_masterkeys = utils.postgres_count_masterkeys(show_all=False, key_type="local_user")
            st.metric("Local User Masterkeys", f"{dec_local_user_masterkeys} / {local_user_masterkeys}")
        with cols[3]:
            machine_masterkeys = utils.postgres_count_masterkeys(key_type="machine")
            dec_machine_masterkeys = utils.postgres_count_masterkeys(show_all=False, key_type="machine")
            st.metric("Machine Masterkeys", f"{dec_machine_masterkeys} / {machine_masterkeys}")

    if chosen_tab == "masterkeys":
        # trigger getting the password data in case we have a cache hit
        df = utils.get_masterkeys()

        # force a cache reset if "df_loaded" is missing - this happens on a hard reload
        if "df_loaded" not in st.session_state:
            st.cache_data.clear()
            print("[!] Resetting cache")
            df = utils.get_masterkeys()

        st.subheader("Submit Keys")
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

        cookies.save()

        if (
            "nemesus_project" in cookies and cookies["nemesus_project"] != ""
            and "nemesis_operator" in cookies and cookies["nemesis_operator"] != ""
            and "nemesis_source" in cookies and cookies["nemesis_source"] != ""
            and "nemesis_expiration_days" in cookies and cookies["nemesis_expiration_days"] != ""
        ):

            authentication_data = {}
            submission_id = ""

            with st.form("key_submission", clear_on_submit=True):
                cols = st.columns(3)
                with cols[0]:
                    plaintext_password = st.text_input("Password", placeholder="<username>:<password/NTLM hash>")
                    if plaintext_password:
                        if ":" not in plaintext_password:
                            st.error("The required format is `<username>:<password/NTLM hash>`")
                        else:
                            i = plaintext_password.find(":")
                            username = plaintext_password[:i]
                            password = plaintext_password[i + 1:]
                            cred_type = "password"

                            if re.match("[a-zA-Z0-9]{32}$", password):
                                cred_type = "ntlm_hash"

                            authentication_data = {
                                "type": cred_type,
                                "username": username,
                                "data": password
                            }
                with cols[1]:
                    dpapi_system = st.text_input("DPAPI_SYSTEM", placeholder="DPAPI_SYSTEM LSA secret")
                    if dpapi_system:
                        if not re.match("^(([a-fA-F0-9]{40})|([a-fA-F0-9]{80}))$", dpapi_system):
                            st.error("Valid format for DPAPI_SYSTEM is 40 or 80 alphanumeric characters")
                        else:
                            authentication_data = {
                                "type": "dpapi_system",
                                "data": dpapi_system
                            }
                with cols[2]:
                    dec_masterkey = st.text_input("Plaintext Masterkey", placeholder="GUID:SHA1")
                    if dec_masterkey:
                        if not re.match("^\{?([0-9a-fA-F]){8}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){12}\}?:([a-fA-F0-9]{40})$", dec_masterkey):
                            st.error("The required format is `GUID:SHA1`")
                        else:
                            authentication_data = {
                                "type": "dpapi_masterkey",
                                "data": dec_masterkey
                            }

                submitted = st.form_submit_button(label="Submit")

                if submitted and authentication_data and (plaintext_password or dec_masterkey or dpapi_system):
                    submission_time = datetime.datetime.utcnow()
                    expiration = submission_time + datetime.timedelta(days=int(cookies["nemesis_expiration_days"]))
                    submission_time_s = submission_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                    expiration_s = expiration.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                    metadata = {
                        "agent_id": cookies["nemesis_operator"],
                        "agent_type": "dashboard",
                        "automated": False,
                        "data_type": "authentication_data",
                        "expiration": expiration_s,
                        "source": cookies["nemesis_source"],
                        "project": cookies["nemesus_project"],
                        "timestamp": submission_time_s,
                    }
                    submission_id = utils.nemesis_post_data({"metadata": metadata, "data": [authentication_data]})
                    if submission_id:
                        st.success(f"Successful Nemesis submission: {submission_id}", icon="✅")
                        time.sleep(5)
                        st.cache_data.clear()
                        st.experimental_rerun()

        gb = GridOptionsBuilder.from_dataframe(df)

        # build and display our grid
        grid = AgGrid(
            df,
            gridOptions=gb.build(),
            width="100%",
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            fit_columns_on_grid_load=True,
        )