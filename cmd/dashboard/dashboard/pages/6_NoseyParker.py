# Standard Libraries
import os
import urllib

# 3rd Party Libraries
import streamlit as st
import templates
import utils
from annotated_text import annotated_text, annotation

utils.header()

page_size = int(os.environ["PAGE_SIZE"])
nemesis_http_server = os.environ.get("NEMESIS_HTTP_SERVER") or ""


if st.session_state["authentication_status"]:
    with st.expander("About NoseyParker Search"):
        st.markdown(
            """
        This page lists all files that have NoseyParker results.

        Results are grouped by each file with matching results.
        """
        )

    # default values
    if "np_page" not in st.session_state:
        st.session_state.np_page = 1

    # get parameters in url
    para = st.experimental_get_query_params()
    if "np_page" in para:
        st.experimental_set_query_params()
        st.session_state.np_page = int(para["np_page"][0])

    from_i = (st.session_state.np_page - 1) * page_size
    results = utils.elastic_np_search(from_i, page_size)

    if results != {}:
        total_hits = results["hits"]["total"]["value"]
        num_results = len(results["hits"]["hits"])

        if total_hits > 0:
            st.write(templates.number_of_results(total_hits, results["took"] / 1000), unsafe_allow_html=True)

            for i in range(num_results):
                object_id = results["hits"]["hits"][i]["_source"]["objectId"]
                download_url = f"{nemesis_http_server}/api/download/{object_id}"
                path = results["hits"]["hits"][i]["_source"]["path"]
                source = ""
                if "metadata" in results["hits"]["hits"][i]["_source"] and "source" in results["hits"]["hits"][i]["_source"]["metadata"]:
                    source = results["hits"]["hits"][i]["_source"]["metadata"]["source"]

                with st.expander(f"{source} : {path}"):
                    st.write(
                        f"""
                        <a href="{download_url}">
                            Download File
                        </a>
                    """,
                        unsafe_allow_html=True,
                    )
                    st.divider()
                    for ruleMatch in results["hits"]["hits"][i]["_source"]["noseyparker"]["ruleMatches"]:
                        for match in ruleMatch["matches"]:
                            rule_name = match["ruleName"]
                            before = match["snippet"]["before"].replace("\n\t", " ")
                            matching = match["snippet"]["matching"]
                            after = match["snippet"]["after"].replace("\n\t", " ")

                            st.write(f"<b>Rule</b>: {rule_name}", unsafe_allow_html=True)
                            annotated_text(annotation(before, "context", color="#8ef"), annotation(matching, "match"), annotation(after, "context", color="#8ef"))
                            st.divider()

            # pagination
            if total_hits > page_size:
                total_pages = (total_hits + page_size - 1) // page_size
                pagination_html = templates.np_pagination(total_pages, st.session_state.np_page)
                st.write(pagination_html, unsafe_allow_html=True)
        else:
            st.write(templates.no_result_html(), unsafe_allow_html=True)
