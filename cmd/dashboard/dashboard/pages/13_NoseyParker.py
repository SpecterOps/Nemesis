# Standard Libraries
import os

# 3rd Party Libraries
import streamlit as st
import templates
import utils
from annotated_text import annotated_text, annotation

page_size = int(os.environ["PAGE_SIZE"])
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")


def render_page(username: str):
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
                file_name = results["hits"]["hits"][i]["_source"]["name"]
                download_url = f"{NEMESIS_HTTP_SERVER}/api/download/{object_id}?name={file_name}"
                view_file_url = f"{NEMESIS_HTTP_SERVER}dashboard/File_Viewer?object_id={object_id}"
                path = results["hits"]["hits"][i]["_source"]["path"]
                sha1 = results["hits"]["hits"][i]["_source"]["hashes"]["sha1"]
                source = ""
                if "metadata" in results["hits"]["hits"][i]["_source"] and "source" in results["hits"]["hits"][i]["_source"]["metadata"]:
                    source = results["hits"]["hits"][i]["_source"]["metadata"]["source"]

                if source:
                    expander_text = f"{source} : **{path}** (SHA1: {sha1})"
                else:
                    expander_text = f"**{path}** (SHA1: {sha1})"

                with st.expander(expander_text):
                    for ruleMatch in results["hits"]["hits"][i]["_source"]["noseyparker"]["ruleMatches"]:
                        for match in ruleMatch["matches"]:
                            if "matching" in match["snippet"]:
                                rule_name = match["ruleName"]

                                matching = match["snippet"]["matching"]
                                try:
                                    match_line = int(match["location"]["sourceSpan"]["start"]["line"])
                                    match_line_length = len(f"{match_line}") + 3
                                    match_line_format = f"{{0:<{match_line_length}}}"
                                except:
                                    match_line = -1
                                    match_line_format = ""

                                if "before" in match["snippet"]:
                                    before_lines = match["snippet"]["before"].replace("\n\t", " ").splitlines()
                                    num_before_lines = len(before_lines)
                                    before = ""
                                    for i in range(len(before_lines)):
                                        line = before_lines[i]
                                        line_prefix = match_line_format.format(f"{(match_line - (num_before_lines - i) + 1)}:")
                                        before += f"{line_prefix}{line}\n"
                                else:
                                    before = ""

                                before = before.strip("\n")

                                after = ""
                                if "after" in match["snippet"]:
                                    after_lines = match["snippet"]["after"].replace("\n\t", " ").splitlines()
                                    if len(after_lines) > 0:
                                        after = f"{after_lines[0]}\n"
                                        for i in range(1, len(after_lines)):
                                            line = after_lines[i]
                                            line_prefix = match_line_format.format(f"{(match_line + i)}:")
                                            after += f"{line_prefix}{line}\n"

                                after = after.strip("\n")

                                st.subheader(f"Rule: {rule_name}", divider="red")

                                st.write(
                                    f"""
                                    <a href="{view_file_url}">
                                        View File Details
                                    </a>
                                    &nbsp; &nbsp; &nbsp;
                                    <a href="{download_url}">
                                        Download File
                                    </a>
                                """,
                                    unsafe_allow_html=True,
                                )
                                st.write("Matching text:")
                                st.code(matching)
                                st.write("Context:")
                                st.code(before + matching + after)
                                st.divider()

            # pagination
            if total_hits > page_size:
                total_pages = (total_hits + page_size - 1) // page_size
                pagination_html = templates.np_pagination(total_pages, st.session_state.np_page)
                st.write(pagination_html, unsafe_allow_html=True)
        else:
            st.write(templates.no_result_html(), unsafe_allow_html=True)


utils.render_nemesis_page(render_page)
