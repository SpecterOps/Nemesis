#!/usr/bin/python3
# from streamlit_chat import message
# 3rd Party Libraries
import requests
import streamlit as st
import utils

NEMESIS_API_URL = "http://enrichment-webapi:9910/"

current_user = utils.header()

if st.session_state["authentication_status"]:

    if "reprocess_button" not in st.session_state:
        st.session_state["reprocess_button"] = False

    if "reprocessing" not in st.session_state:
        st.session_state["reprocessing"] = False

    if "clear_button" not in st.session_state:
        st.session_state["clear_button"] = False

    if "clearing" not in st.session_state:
        st.session_state["clearing"] = False


    # st.subheader("Operation Information")
    # cols = st.columns(4)
    # with cols[0]:
    #     num_hosts = utils.postgres_count_entries("hosts")
    #     st.metric("Total Hosts", num_hosts)
    # with cols[1]:
    #     num_agents = utils.postgres_count_entries("agents")
    #     st.metric("Total Agents", num_agents)
    # st.divider()

    st.subheader("File Information")
    cols = st.columns(5)
    with cols[0]:
        num_plaintext_documents = utils.get_elastic_total_indexed_documents("file_data_plaintext")
        st.metric("Indexed Documents", num_plaintext_documents)
    with cols[1]:
        num_enriched_documents = utils.get_elastic_total_indexed_documents("file_data_enriched")
        st.metric("Processed Files", num_enriched_documents)
    with cols[2]:
        num_np_matches = utils.get_elastic_total_indexed_documents("file_data_enriched", query={"exists": {"field": "noseyparker"}})
        st.metric("NoseyParker Matches", num_np_matches)
    with cols[3]:
        num_hashes = utils.postgres_count_entries("extracted_hashes")
        st.metric("Extracted Hashes", num_hashes)
    with cols[4]:
        num_hashes = utils.postgres_count_entries("extracted_hashes")
        st.metric("Authentication Data", num_hashes)
    st.divider()

    st.subheader("Chromium Information")
    cols = st.columns(4)
    with cols[0]:
        num_cookies = utils.postgres_count_entries("chromium_cookies")
        st.metric("Cookies", num_cookies)
    with cols[1]:
        num_logins = utils.postgres_count_entries("chromium_logins")
        st.metric("Logins", num_logins)
    with cols[2]:
        num_history = utils.postgres_count_entries("chromium_history")
        st.metric("History Entries", num_history)
    with cols[3]:
        num_downloads = utils.postgres_count_entries("chromium_downloads")
        st.metric("Downloads", num_downloads)

    st.divider()

    cols = st.columns(4)

    with cols[0]:
        if st.session_state["reprocessing"]:
            st.success("File reprocessing triggered!")
            st.session_state["reprocessing"] = False
        else:
            if st.button("Reprocess All Data", key="reprocess_data1"):
                st.session_state["reprocess_button"] = not st.session_state["reprocess_button"]
            if st.session_state["reprocess_button"]:
                st.warning("Are you really, REALLY, sure you want to reprocess everything?", icon="🚨")
                if st.button("Yes I know what I'm doing", key="reprocess_data2"):
                    st.session_state["reprocessing"] = True
                    try:
                        requests.post(f"{NEMESIS_API_URL}reprocess", timeout=0.1)
                        st.experimental_rerun()
                    except requests.exceptions.ReadTimeout:
                        st.experimental_rerun()
                    except Exception as e:
                        st.warning(f"Error posting to Nemesis URL {NEMESIS_API_URL}reprocess : {e}", icon="⚠️")

    with cols[1]:
        if st.session_state["clearing"]:
            st.success("Data clearing triggered!")
            st.session_state["clearing"] = False
        else:
            if st.button("Clear All Data", key="data_clear1"):
                st.session_state["clear_button"] = not st.session_state["clear_button"]
            if st.session_state["clear_button"]:
                st.warning("Are you really, REALLY, sure you want to clear all data?", icon="🚨")
                if st.button("Yes I know what I'm doing", key="data_clear2"):
                    st.session_state["clearing"] = True
                    try:
                        requests.post(f"{NEMESIS_API_URL}reset", timeout=0.1)
                        st.experimental_rerun()
                    except requests.exceptions.ReadTimeout:
                        st.experimental_rerun()
                    except Exception as e:
                        st.warning(f"Error posting to Nemesis URL {NEMESIS_API_URL}reset : {e}", icon="⚠️")

    footer="""<style>
.footer {
position: fixed;
left: 0;
bottom: 0;
width: 50%;
text-align: center;
}
</style>
<div class="footer">
<p>&nbsp;&nbsp;Powered by <a style='text-align: center;' href="https://specterops.io/" target="_blank">SpecterOps</a></p>
</div>
"""
    st.markdown(footer, unsafe_allow_html=True)