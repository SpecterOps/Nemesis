# Standard Libraries
import json
import os

# 3rd Party Libraries
import streamlit as st
import templates
import utils

ASSESSMENT_ID = os.environ.get("ASSESSMENT_ID")


def render_page(username: str):
    with st.expander("About Custom Cracklist"):
        st.markdown(
        """
        This page allows you to download the ongoing custom cracklist
        generated from the text extracted from downloaded documents.
        """
        )

    cols = st.columns(2)
    with cols[0]:
        assessment_id = st.text_input(
            "The assessment ID to retrieve the crack list for",
            value=ASSESSMENT_ID,
        )

    with cols[0]:
        count = st.slider('Words to return', min_value=100, max_value=10000, step=100, value=100)

    custom_list = utils.get_custom_crack_list(assessment_id, count)
    if not custom_list:
        st.warning(f"No results for assessment ID {assessment_id}!")
    else:
        try:
            j = json.loads(custom_list)
            if "error" in j:
                e = j["error"]
                st.error(f"Error retrieving list for assessment ID {assessment_id} : {e}")
        except Exception as e:
            st.download_button(
                label="Download custom cracking word list",
                data=custom_list,
                file_name='custom_crack_list.txt',
                mime='text/plain',
            )

utils.render_nemesis_page(render_page)
