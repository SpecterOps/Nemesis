# Standard Libraries
import os

# 3rd Party Libraries
import pandas as pd
import streamlit as st
import utils

# from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy import text as sql_text
from st_aggrid import (
    AgGrid,
    ColumnsAutoSizeMode,
    DataReturnMode,
    GridOptionsBuilder,
    GridUpdateMode,
    JsCode,
)

NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")
POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or ""
PAGE_SIZE = os.environ.get("PAGE_SIZE") or ""
PAGE_SIZE = int(PAGE_SIZE)

engine = create_engine(POSTGRES_CONNECTION_URI)
conn = engine.connect()


def build_about_expander():
    st.title("Hashes")

    with st.expander("About Hashes"):
        st.markdown(
            """
        This page shows hashes that have been extracted from processed Nemesis data.
        """
        )


def render_page(username: str):
    build_about_expander()

    object_id = utils.get_single_valued_param("object_id")

    query = """
SELECT
    agent_id,
    timestamp,
    hash_type,
    hash_value,
    is_cracked,
    plaintext_value,
    originating_object_id::varchar as object_id
FROM extracted_hashes
"""
    params = {}
    if object_id:
        query += " WHERE originating_object_id = :object_id"
        params["object_id"] = object_id

        st.write("Filters are currently applied.")
        if st.button("Clear Filters"):
            st.experimental_set_query_params()

    df = pd.read_sql_query(sql_text(query), conn, params=params)

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(groupable=True)

    gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=PAGE_SIZE)

    gb.configure_column("agent_id", hide=True)
    gb.configure_column("timestamp", sort="desc")

    js_link_code = f"""
        class UrlCellRenderer {{
            init(params) {{
                var link = "{NEMESIS_HTTP_SERVER}dashboard/File_Viewer?object_id=" + params.value;
                this.eGui = document.createElement('a');
                this.eGui.innerText = 'View Originating File';
                this.eGui.setAttribute('href', link);
                this.eGui.setAttribute('style', "text-decoration:none");
                this.eGui.setAttribute('target', "_blank");
            }}
            getGui() {{
                return this.eGui;
            }}
        }}
        """
    gb.configure_column("object_id", headerName="Originating Object", cellRenderer=JsCode(js_link_code))

    grid = AgGrid(
        df,
        gridOptions=gb.build(),
        width="100%",
        data_return_mode=DataReturnMode.AS_INPUT,
        update_mode=GridUpdateMode.VALUE_CHANGED,
        fit_columns_on_grid_load=True,
        allow_unsafe_jscode=True,
        allow_unsafe_html=True,
        # columns_auto_size_mode=ColumnsAutoSizeMode.FIT_CONTENTS,
        custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
    )


utils.render_nemesis_page(render_page)
