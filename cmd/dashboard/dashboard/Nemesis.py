#!/usr/bin/python3

# 3rd Party Libraries
import pandas as pd
import requests
import streamlit as st
import streamlit.components.v1 as components
import utils
from streamlit.web.server.app_static_file_handler import \
    SAFE_APP_STATIC_FILE_EXTENSIONS

SAFE_APP_STATIC_FILE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp")

NEMESIS_API_URL = "http://enrichment-webapi:9910/"


def build_page(username: str):
    if "reprocess_button" not in st.session_state:
        st.session_state["reprocess_button"] = False

    if "reprocessing" not in st.session_state:
        st.session_state["reprocessing"] = False

    if "clear_button" not in st.session_state:
        st.session_state["clear_button"] = False

    if "clearing" not in st.session_state:
        st.session_state["clearing"] = False

    st.title("Nemesis Overview")

    st.subheader("Files")

    num_processed_files = utils.get_elastic_total_indexed_documents("file_data_enriched")
    num_triaged_filess = utils.postgres_count_triaged_files()
    num_untriaged_files = num_processed_files - num_triaged_filess
    num_plaintext_documents = utils.get_elastic_total_indexed_documents("file_data_plaintext")
    num_np_matches = utils.get_elastic_total_indexed_documents("file_data_enriched", query={"exists": {"field": "noseyparker"}})
    num_hashes = utils.postgres_count_entries("extracted_hashes")
    auth_data = utils.postgres_count_entries("authentication_data")

    df = pd.DataFrame(
        [
            {"Stat": "Processed Files", "Value": num_processed_files},
            {"Stat": "Triaged Files", "Value": num_triaged_filess},
            {"Stat": "Untriaged Files", "Value": num_untriaged_files},
            {"Stat": "Plaintext Documents", "Value": num_plaintext_documents},
            {"Stat": "NoseyParker Matches", "Value": num_np_matches},
            {"Stat": "Extracted Hashes", "Value": num_hashes},
            {"Stat": "Extracted Credentials", "Value": auth_data},
        ]
    )

    st.dataframe(
        data=df,
        hide_index=True,
        width=500
    )
    st.divider()

    st.subheader("Chromium")

    num_cookies = utils.postgres_count_entries("chromium_cookies")
    num_logins = utils.postgres_count_entries("chromium_logins")
    num_history = utils.postgres_count_entries("chromium_history")
    num_downloads = utils.postgres_count_entries("chromium_downloads")

    df2 = pd.DataFrame(
        [
            {"Stat": "Cookies", "value": num_cookies},
            {"Stat": "Logins", "value": num_logins},
            {"Stat": "History Entries", "value": num_history},
            {"Stat": "Extracted Hashes", "value": num_downloads},
        ]
    )

    st.dataframe(
        data=df2,
        hide_index=True,
        width=500
    )
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
                        st.rerun()
                    except requests.exceptions.ReadTimeout:
                        st.rerun()
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
                        st.rerun()
                    except requests.exceptions.ReadTimeout:
                        st.rerun()
                    except Exception as e:
                        st.warning(f"Error posting to Nemesis URL {NEMESIS_API_URL}reset : {e}", icon="⚠️")

    footer = """<style>
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


utils.render_nemesis_page(build_page)
