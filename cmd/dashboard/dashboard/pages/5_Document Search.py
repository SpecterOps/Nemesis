# Standard Libraries
import os
import urllib.parse

# 3rd Party Libraries
import extra_streamlit_components as stx
import streamlit as st
import templates
import utils

PAGE_SIZE = int(os.environ["PAGE_SIZE"])


def build_about_expander():
    with st.expander("About Document Search"):
        st.markdown(
            """
        This page searches the extracted plaintext from every convertible document
        ingested into Nemesis as well as any downloaded source code.

        Text is extracted with Apache Tika and indexed into Elasticsearch.

        Semantic search is powered by searching pre-computed dense vector embeddings,
        vectoring the input query and returning document chunks that are the semantically
        closest to the input.
        """
        )


def build_page(username: str):
    build_about_expander()

    # default values
    if "text_search" not in st.session_state:
        st.session_state.text_search = None
    if "text_page" not in st.session_state:
        st.session_state.text_page = 1

    # get parameters in url
    para = st.experimental_get_query_params()
    if "text_search" in para:
        st.experimental_set_query_params()
        st.session_state.text_search = urllib.parse.unquote(para["text_search"][0])
    if "text_page" in para:
        st.experimental_set_query_params()
        st.session_state.text_page = int(para["text_page"][0])

    chosen_tab = stx.tab_bar(
        data=[
            stx.TabBarItemData(id="text_search", title="Text Search", description="Search text extracted from downloaded files"),
            stx.TabBarItemData(id="source_code_search", title="Source Code Search", description="Search downloaded source code files"),
            stx.TabBarItemData(id="semantic_search", title="Semantic Search", description="Semantic search over extracted text"),
        ],
        default="text_search",
    )

    if chosen_tab == "text_search":
        if st.session_state.text_search is None:
            search_term = st.text_input("Enter search term(s):")
        else:
            search_term = st.text_input("Enter search term(s):", st.session_state.text_search)

        if not search_term:
            return

        st.session_state.text_search = search_term
        from_i = (st.session_state.text_page - 1) * PAGE_SIZE

        results = utils.elastic_text_search(search_term, from_i, PAGE_SIZE)
        if not results:
            st.write(templates.no_result_html(), unsafe_allow_html=True)
            return

        total_hits = results["hits"]["total"]["value"]
        num_results = len(results["hits"]["hits"])

        if total_hits <= 0:
            return

        st.write(templates.number_of_results(total_hits, results["took"] / 1000), unsafe_allow_html=True)

        for i in range(num_results):
            res = utils.simplify_es_text_result(results["hits"]["hits"][i])

            originatingObjectPath = res["originatingObjectPath"]
            originatingObjectId = res["originatingObjectId"]
            originatingObjectURL = res["originatingObjectURL"]
            if "originatingObjectConvertedPdfUrl" in res:
                originatingObjectConvertedPdfUrl = res["originatingObjectConvertedPdfUrl"]
                pdf_url = f"{originatingObjectConvertedPdfUrl}&action=view"
            else:
                pdf_url = ""

            highlights = res["highlights"]
            source = ""
            if "metadata" in res and "source" in res["metadata"]:
                source = res["metadata"]["source"]
            if "wordCount" in res:
                length = res["wordCount"]
            else:
                length = "-1"

            (header, highlights, footer) = templates.text_search_result(
                i=i,
                url=originatingObjectURL,
                pdf_url=pdf_url,
                source=source,
                path=originatingObjectPath,
                highlights=highlights,
                length=length,
                originating_object_id=originatingObjectId,
            )
            st.write(header, unsafe_allow_html=True)
            st.markdown(highlights)
            st.write(footer, unsafe_allow_html=True)

        # pagination
        if total_hits > PAGE_SIZE:
            total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
            pagination_html = templates.text_pagination(total_pages, search_term, st.session_state.text_page)
            st.write(pagination_html, unsafe_allow_html=True)

    elif chosen_tab == "source_code_search":
        if st.session_state.text_search is None:
            search_term = st.text_input("Enter search term(s):")
        else:
            search_term = st.text_input("Enter search term(s):", st.session_state.text_search)

        if search_term != "":
            st.session_state.text_search = search_term
            from_i = (st.session_state.text_page - 1) * PAGE_SIZE
            results = utils.elastic_sourcecode_search(search_term, from_i, PAGE_SIZE)
            if results != {}:
                total_hits = results["hits"]["total"]["value"]
                num_results = len(results["hits"]["hits"])

                if total_hits > 0:
                    st.write(templates.number_of_results(total_hits, results["took"] / 1000), unsafe_allow_html=True)

                    for i in range(num_results):
                        res = utils.simplify_es_text_result(results["hits"]["hits"][i])
                        path = res["path"]
                        download_url = res["downloadURL"]
                        object_id = res["objectId"]
                        # extension = res["extension"]
                        language = res["language"]
                        name = res["name"]
                        path = res["path"]
                        size = res["size"]
                        highlights = res["highlights"]
                        source = ""
                        if "metadata" in res and "source" in res["metadata"]:
                            source = res["metadata"]["source"]

                        (header, highlights, footer) = templates.sourcecode_search_result(
                            i=i,
                            object_id=object_id,
                            download_url=download_url,
                            source=source,
                            path=path,
                            name=name,
                            language=language,
                            highlights=highlights,
                            size=size,
                        )
                        st.write(header, unsafe_allow_html=True)
                        st.code(highlights, language=language.lower())
                        st.write(footer, unsafe_allow_html=True)

                    # pagination
                    if total_hits > PAGE_SIZE:
                        total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
                        pagination_html = templates.text_pagination(total_pages, search_term, st.session_state.text_page)
                        st.write(pagination_html, unsafe_allow_html=True)
                else:
                    st.write(templates.no_result_html(), unsafe_allow_html=True)

    elif chosen_tab == "semantic_search":
        cols = st.columns(2)
        with cols[1]:
            num_results = st.slider("Select the number of results to return", min_value=0, max_value=10, value=4, step=1)

        if st.session_state.text_search is None:
            search_term = st.text_input("Enter search term(s):")
        else:
            search_term = st.text_input("Enter search term(s):", st.session_state.text_search)

        if search_term != "":
            st.session_state.text_search = search_term

            try:
                json_results = utils.semantic_search(search_term, num_results)
                if not json_results or "results" not in json_results:
                    st.warning("No results retrieved from semantic search, service might be busy")
                else:
                    for result in json_results["results"]:
                        (header, text, footer) = templates.semantic_search_result(result)
                        st.write(header, unsafe_allow_html=True)
                        st.write(text, unsafe_allow_html=False)
                        st.write(footer, unsafe_allow_html=True)
                        # st.divider()
            except Exception as e:
                st.error(f"Exception: {e}")


utils.render_nemesis_page(build_page)
