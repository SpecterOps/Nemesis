# Standard Libraries
import os

# 3rd Party Libraries
import pandas as pd
import streamlit as st
import utils

# from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy import text as sql_text
from st_aggrid import AgGrid, DataReturnMode, GridOptionsBuilder, GridUpdateMode, JsCode

PUBLIC_KIBANA_URL = os.environ.get("PUBLIC_KIBANA_URL") or ""
POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or ""
PAGE_SIZE = os.environ.get("PAGE_SIZE") or ""
PAGE_SIZE = int(PAGE_SIZE)

engine = create_engine(POSTGRES_CONNECTION_URI)
conn = engine.connect()


utils.header()

if st.session_state["authentication_status"]:
    st.title("Hashes")

    with st.expander("About Hashes"):
        st.markdown(
            """
        This page shows hashes that have been extracted from processed Nemesis data.
        """
        )

    query = "SELECT agent_id, timestamp, hash_type, hash_value, is_cracked, plaintext_value, originating_object_id::varchar as object_id from extracted_hashes"
    df = pd.read_sql_query(sql_text(query), conn)

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(groupable=True)

    gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=PAGE_SIZE)

    gb.configure_column("agent_id", hide=True)
    gb.configure_column("timestamp", hide=True)

    js_link_code = """
            class UrlCellRenderer {
            init(params) {
                var link = "%sapp/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'" + params.value + "')))))&_g=(time:(from:now-1y%%2Fd,to:now))";
                this.eGui = document.createElement('a');
                this.eGui.innerText = 'Link To Originating File';
                this.eGui.setAttribute('href', link);
                this.eGui.setAttribute('style', "text-decoration:none");
                this.eGui.setAttribute('target', "_blank");
            }
            getGui() {
                return this.eGui;
            }
            }
        """ % (
        PUBLIC_KIBANA_URL
    )

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
    )
