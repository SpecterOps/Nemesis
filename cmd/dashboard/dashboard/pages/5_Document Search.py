# Standard Libraries
import os
import urllib.parse

# 3rd Party Libraries
import extra_streamlit_components as stx
import streamlit as st
import templates
import utils

PAGE_SIZE = 10

def build_about_expander():
    with st.expander("About Document Search"):
        st.markdown(
            """
        This page searches the extracted plaintext from every convertible document
        ingested into Nemesis as well as any downloaded source code.

        Text is extracted with Apache Tika and indexed into Elasticsearch. The text
        of each document is also broken into chunks of ~500 tokens/words each which
        are also indexed into Elasticsearch along with generated vector embeddings.

        **Full Document Search** searches for literal phrases over complete documents,
        returning each unique document result. By default it searches through text
        extracted from documents, but indexed source code can be searched by selecting
        the "source_code" index in the Search Filters.

        **Text Chunk Search** searches over the text chunks extracted from plaintext documents.
        If "Use Hybrid Vector Search" is selected, fuzzy/BM25 search is done by Elastic
        over the file name and indexed text, and a embedding is generated from the query
        to also search over the indexed emebdding vectors. Reciprocal Rank Fusion is then
        used to rerank the results and return the top X.

        If _Use Hybrid Vector Search_ is not selected, just the fuzzy/BM25 search is
        performed without embedding vector enrichment.

        For both search types, the Search Filters expander allows you to specify a wildcard
        path for files to include or exclude from each. For example: C:\\Temp\\*, or *.pdf
        """
        )


def build_page(username: str):
    build_about_expander()

    # default values
    if "text_search" not in st.session_state:
        st.session_state.text_search = None
    if "text_page" not in st.session_state:
        st.session_state.text_page = 1
    if "search_index" not in st.session_state:
        st.session_state.search_index = 0
    if "current_tab" not in st.session_state:
        st.session_state.current_tab = "full_document"

    # get parameters in url
    if "text_search" in st.query_params:
        st.session_state.text_search = urllib.parse.unquote(st.query_params["text_search"])
    if "text_page" in st.query_params:
        st.session_state.text_page = int(st.query_params["text_page"])
    if "search_index" in st.query_params:
        st.session_state.search_index = int(st.query_params["search_index"])
    if "current_tab" in st.query_params:
        st.session_state.current_tab = st.query_params["current_tab"]

    chosen_tab = stx.tab_bar(
        data=[
            stx.TabBarItemData(id="full_document", title="Full Document Search", description="Over Complete Documents"),
            stx.TabBarItemData(id="text_chunk_search", title="Text Chunk Search", description="Over Extracted Text Chunks"),
        ],
        default=st.session_state.current_tab
    )

    st.session_state.current_tab = chosen_tab
    st.query_params["current_tab"] = chosen_tab

    if chosen_tab == "full_document":
        st.subheader("Full Document Search")
        st.markdown("_Searches Over Complete/Unique Documents, a la Google_")

        with st.expander("Search Filters"):
            cols = st.columns(3)
            file_path_include = ""
            file_path_exclude = ""
            with cols[0]:
                if st.session_state.search_index:
                    default_index = int(st.session_state.search_index)
                else:
                    default_index = 0
                search_index = st.selectbox(
                    "Search index to use",
                    ["extracted_plainext", "source_code"],
                    index=default_index
                )
            with cols[1]:
                file_path_include = st.text_input("Enter file 'path' to include (wildcard == *):")
            with cols[2]:
                file_path_exclude = st.text_input("Enter file 'path' to exclude (wildcard == *):")

        if search_index == "extracted_plainext":
            text_search_term = st.text_input("Enter search term (wildcard == *):", st.session_state.text_search)

            if not text_search_term:
                return

            # if we get a different term, it means a new search was initiated
            if text_search_term != st.session_state.text_search:
                st.session_state.text_search = text_search_term
                st.session_state.text_page = 1
                st.query_params["text_search"] = st.session_state.text_search
                st.query_params["text_page"] = st.session_state.text_page
                st.query_params["search_index"] = st.session_state.search_index

            from_i = (st.session_state.text_page - 1) * PAGE_SIZE

            results = utils.elastic_text_search(text_search_term, file_path_include, file_path_exclude, from_i, PAGE_SIZE)
            if not results:
                st.write(templates.no_result_html(), unsafe_allow_html=True)
                return

            total_hits = results["hits"]["total"]["value"]
            num_results = len(results["hits"]["hits"])

            if total_hits <= 0:
                st.warning("No document results!")
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
                    i=(from_i + i),
                    url=originatingObjectURL,
                    pdf_url=pdf_url,
                    source=source,
                    path=originatingObjectPath,
                    highlights=highlights,
                    length=length,
                    originating_object_id=originatingObjectId,
                )
                st.write(header, unsafe_allow_html=True)
                st.code(utils.text_to_chunk_display(highlights), None)
                st.write(footer, unsafe_allow_html=True)

            # pagination
            if total_hits > PAGE_SIZE:
                total_pages = (total_hits + PAGE_SIZE - 1) // PAGE_SIZE
                pagination_html = templates.text_pagination(total_pages, text_search_term, st.session_state.text_page, "text_search")
                st.write(pagination_html, unsafe_allow_html=True)
        else:
            code_search_term = st.text_input("Enter search term (wildcard == *):", st.session_state.text_search)

            if not code_search_term:
                return

            # if we get a different term, it means a new search was initiated
            if code_search_term != st.session_state.text_search:
                st.session_state.text_search = code_search_term
                st.session_state.text_page = 1
                st.query_params["text_search"] = st.session_state.text_search
                st.query_params["text_page"] = st.session_state.text_page
                st.query_params["search_index"] = st.session_state.search_index

            from_i = (st.session_state.text_page - 1) * PAGE_SIZE

            results = utils.elastic_sourcecode_search(code_search_term, file_path_include, file_path_exclude, from_i, PAGE_SIZE)
            if not results:
                st.write(templates.no_result_html(), unsafe_allow_html=True)
                return

            total_hits = results["hits"]["total"]["value"]
            num_results = len(results["hits"]["hits"])

            if total_hits <= 0:
                st.warning("No source code results!")
                return

            st.write(templates.number_of_results(total_hits, results["took"] / 1000), unsafe_allow_html=True)

            for i in range(num_results):
                res = utils.simplify_es_text_result(results["hits"]["hits"][i])
                path = res["path"]
                download_url = res["downloadURL"]
                object_id = res["objectId"]
                language = res["language"]
                name = res["name"]
                path = res["path"]
                size = res["size"]
                highlights = res["highlights"]
                source = ""
                if "metadata" in res and "source" in res["metadata"]:
                    source = res["metadata"]["source"]

                (header, highlights, footer) = templates.sourcecode_search_result(
                    i=(from_i + i),
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
                pagination_html = templates.text_pagination(total_pages, code_search_term, st.session_state.text_page, "source_code_search")
                st.write(pagination_html, unsafe_allow_html=True)

    elif chosen_tab == "text_chunk_search":
        st.subheader("Text Chunk Search")
        st.markdown("_Searches Over Text Chunks Extracted From Documents_")

        if "text_search" in st.query_params:
            del st.query_params["text_search"]
        if "text_page" in st.query_params:
            del st.query_params["text_page"]
        if "search_index" in st.query_params:
            del st.query_params["search_index"]

        with st.expander("Search Filters"):
            cols = st.columns(2)
            file_path_include = ""
            file_path_exclude = ""
            with cols[0]:
                file_path_include = st.text_input("Enter file 'path' to include (wildcard == *):")
            with cols[1]:
                file_path_exclude = st.text_input("Enter file 'path' to exclude (wildcard == *):")

        search_term = st.text_input("Enter search term(s):")

        cols = st.columns(3)
        with cols[1]:
            use_hybrid = st.toggle("Use Hybrid Vector Search",
                                   True,
                                   help="Use Hybrid Search/Reciprocal Rank Fusion with text embedding vectors instead of just fuzzy text search.")
        with cols[2]:
            num_results = st.slider("Select the number of results to return",
                                    min_value=1,
                                    max_value=100,
                                    value=50,
                                    step=1)

        if search_term != "":
            st.session_state.text_search = search_term

            try:
                json_results = utils.text_search(search_term, use_hybrid, file_path_include, file_path_exclude, num_results)
                if json_results and "error" in json_results:
                    error = json_results["error"]
                    if "index_not_found_exception" in error:
                        st.warning("No text has been indexed!")
                    else:
                        st.error(f"Error from NLP service: {error}")
                elif not json_results or "results" not in json_results:
                    st.warning("No results retrieved from semantic search, service might be busy")
                else:
                    if json_results and json_results["results"] and len(json_results["results"]) > 0:
                        for result in json_results["results"]:
                            header = templates.semantic_search_result(result)
                            st.subheader("", divider="red")
                            st.markdown(header, unsafe_allow_html=True)
                            st.markdown("")
                            with st.expander("Text Block"):
                                st.code(result["text"], None)
                        st.subheader("", divider="red")
                    else:
                        st.warning("No results retrieved from semantic search")


            except Exception as e:
                st.error(f"Exception: {e}")



utils.render_nemesis_page(build_page)
