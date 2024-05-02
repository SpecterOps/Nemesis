# Standard Libraries
import logging
import os

# 3rd Party Libraries
import pandas as pd
import streamlit as st
import templates
import utils
from st_aggrid import (AgGrid, ColumnsAutoSizeMode, DataReturnMode,
                       GridOptionsBuilder, GridUpdateMode, JsCode)
from streamlit_cookies_manager import CookieManager

NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER")
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

# Get the Elasticsearch client
logging.getLogger("elasticsearch").setLevel(logging.ERROR)
es_client = utils.wait_for_elasticsearch()


# only execute the main functionality if the user is authenticated
def render_page(username: str):
    cookies = CookieManager()
    if not cookies.ready():
        st.stop()

    with st.expander("About Credentials"):
        st.markdown(
            """
        This page shows plaintext password authentication data that has been
        extracted from processed Nemesis data. The `triage` tags (Useful/Not Useful/Unknown)
        can be set by clicking the `triage` column. These values are set back in the
        database for tracking, and can also be used for filtering the table.

        The table can also be exported as csv or Excel by right clicking and choosing the
        appropriate option.
        """
        )

    # these are our filter tags
    triage_tags = ["useful", "not useful", "unknown", None]

    with st.expander("Triage tags"):
        options = st.multiselect("Triage Tags", triage_tags, triage_tags, on_change=st.cache_data.clear)

    object_id = utils.get_single_valued_param("object_id")

    # trigger getting the password data in case we have a cache hit
    df = utils.get_password_data(object_id)

    # force a cache reset if "df_loaded" is missing - this happens on a hard reload
    if "df_loaded" not in st.session_state:
        st.cache_data.clear()
        print("[!] Resetting cache")
        df = utils.get_password_data(object_id)
        # if we're hard reloading, make sure the "display_object_id" cookie is wiped out
        cookies["display_object_id"] = None
        cookies.save()

    df_filtered = df[df["triage"].isin(options)]

    if df_filtered is None:
        st.error("No `authentication_data` retrieved!", icon="🚨")
    elif df_filtered.empty:
        st.error("No `authentication_data` exists!", icon="🚨")
    elif df_filtered.empty:
        st.error("No matching `authentication_data` for the given filters!")
    else:
        gb = GridOptionsBuilder.from_dataframe(df_filtered)
        gb.configure_default_column(groupable=True)

        # configure pagination with our PAGE_SIZE
        gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=PAGE_SIZE)

        # hide some metadata columns from the user
        gb.configure_column("unique_db_id", hide=True)
        gb.configure_column("agent_id", hide=True)
        gb.configure_column("timestamp", sort="desc")

        gb.configure_column("username", wrapText=True, autoHeight=True)
        gb.configure_column("data", wrapText=True, autoHeight=True)
        gb.configure_column("url", wrapText=True, autoHeight=True)

        # set the "triage" column to be editable with our "triage_tags" values as a popup modal
        gb.configure_column(
            "triage",
            editable=True,
            groupable=True,
            cellEditor="agRichSelectCellEditor",
            cellEditorParams={"values": triage_tags},
            cellEditorPopup=True,
            singleClickEdit=True,
        )

        # set the "notes" column to be editable
        gb.configure_column("notes", editable=True, groupable=True, singleClickEdit=True)

        # custom JavaScript code that constructs a public Kibana link from a supplied
        #   object_id and lets you render the HTML link clickable
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

        # set the object_id column to use the custom Kibana link JavaScript code
        gb.configure_column("object_id", headerName="Originating Object", cellRenderer=JsCode(js_link_code))

        # custom JavaScript code that manually sets an applied row as "selected"
        #   so that row is returned with grid["selected_rows"] on editing
        # Yes, this is a hack, but it's because we can't otherwise easily return
        #   _just_ the  row that's been edited instead of the entire stupid dataframe
        js_cell_changed = JsCode(
            """
            function(e) {
                let api = e.api;
                let rowIndex = e.rowIndex;
                let col = e.column.colId;
                let rowNode = api.getDisplayedRowAtIndex(rowIndex);
                rowNode.setSelected(true);
            };
        """
        )

        # the triage column is the only editable column, so don't need to otherwise constrain here
        gb.configure_grid_options(onCellValueChanged=js_cell_changed)

        st.write(templates.number_of_results(df.shape[0]), unsafe_allow_html=True)
        # build and display our grid
        grid = AgGrid(
            df_filtered,
            gridOptions=gb.build(),
            height="600px",
            data_return_mode=DataReturnMode.AS_INPUT,
            update_mode=GridUpdateMode.VALUE_CHANGED | GridUpdateMode.SELECTION_CHANGED,
            fit_columns_on_grid_load=True,
            allow_unsafe_jscode=True,
            allow_unsafe_html=True,
            columns_auto_size_mode=ColumnsAutoSizeMode.FIT_CONTENTS,
            custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
        )

        for row in grid["selected_rows"]:
            if row["triage"]:
                utils.update_triage_table(row["unique_db_id"], "authentication_data", username, row["triage"], row["object_id"])
            if row["notes"]:
                utils.update_notes_table(row["unique_db_id"], "authentication_data", username, row["notes"])


utils.render_nemesis_page(render_page)
