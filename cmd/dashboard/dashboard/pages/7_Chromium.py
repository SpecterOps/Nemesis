# Standard Libraries
import os
import re
from typing import List

# 3rd Party Libraries
import extra_streamlit_components as stx
import streamlit as st
import utils
from st_aggrid import (
    AgGrid,
    ColumnsAutoSizeMode,
    DataReturnMode,
    GridOptionsBuilder,
    GridUpdateMode,
    JsCode,
)
from streamlit_searchbox import st_searchbox
from streamlit_toggle import st_toggle_switch

PUBLIC_KIBANA_URL = os.environ.get("PUBLIC_KIBANA_URL") or ""
POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
DB_ITERATION_SIZE = os.environ.get("DB_ITERATION_SIZE") or "1000"
PAGE_SIZE = os.environ.get("PAGE_SIZE") or "10"
PAGE_SIZE = int(PAGE_SIZE)

global sources
sources: List[str] = []
global usernames
usernames = []
global cookie_names
cookie_names = []
global cookie_sites
cookie_sites = []


def search_sources(search_term: str) -> List[str]:
    global sources
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), sources))


def search_usernames(search_term: str) -> List[str]:
    global usernames
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), usernames))


def search_cookie_names(search_term: str) -> List[str]:
    global cookie_names
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), cookie_names))


def search_cookie_sites(search_term: str) -> List[str]:
    global cookie_sites
    return list(filter(lambda v: re.match(f".*{re.escape(search_term)}.*", v, re.IGNORECASE), cookie_sites))


def build_about_bar():
    with st.expander("About Chromium"):
        st.markdown(
            """
            This page will let you search for a source system, username, browser
            type, + cookie and/or site name to filter for existing Chromium cookies or logins.

            for cookies, click the "Show expired" button to show all cookies instead of just those
            that are not expired (the detault).
        """
        )


def get_search_filters():
    query_params = st.experimental_get_query_params()

    # pull our specified tab from the query parameters, otherwise use "cookies" as the default
    if "tab" not in query_params or not query_params["tab"]:
        query_params["tab"] = ["cookies"]

    chosen_tab = stx.tab_bar(
        data=[
            stx.TabBarItemData(id="cookies", title="Cookies", description="Chromium pilfered cookies"),
            stx.TabBarItemData(id="logins", title="Logins", description="Chromium saved logins"),
            stx.TabBarItemData(id="history", title="History", description="Chromium visited URLs"),
            stx.TabBarItemData(id="downloads", title="Downloads", description="Chromium download information"),
        ],
        default=query_params["tab"][0],
    )
    query_params["tab"] = [chosen_tab]
    st.experimental_set_query_params(**query_params)

    return query_params


def build_cookies_tab(authenticated_user: str):
    global usernames
    global sources

    # switches for showing unencrypted + expired cookies
    col1, col2, col3, col4 = st.columns(4)
    with col3:
        show_encrypted = st_toggle_switch(
            label="Show encrypted cookies",
            key="unencrypted_cookie_switch",
            default_value=False,
            label_after=False,
        )

    with col4:
        show_expired = st_toggle_switch(label="Show expired cookies", key="expired_cookie_switch", default_value=False, label_after=False)

    # get all of the unique source names from the nemesis.cookies table
    sources = utils.get_unique_sources("chromium_cookies")

    if not sources or len(sources) == 0:
        st.error("No Chromium cookie data in the database")
        return

    source_selection = st_searchbox(
        search_sources,
        label="Enter a source/computer name to search for:",
        placeholder="Type to search...",
        key="cookies_searchbox_sources",
    )
    if not source_selection:
        source_selection = "%"

    usernames = utils.get_usernames_for_source("cookies", source_selection)

    col1, col2 = st.columns(2)

    with col1:
        username_selection = st_searchbox(
            search_usernames,
            label="Enter a username to search for:",
            placeholder="Type to search...",
            key="cookies_searchbox_usernames",
        )
        if not username_selection:
            username_selection = "%"

    with col2:
        browsers = utils.get_browsers_for_source_username("cookies", source_selection, username_selection)
        browser_selection = st.selectbox("Select a browser:", browsers, key="cookies_select_browser")
        # set our wildcard if we're searching for all browsers
        if browser_selection == "all":
            browser_selection = "%"

    col1, col2 = st.columns(2)

    with col1:
        site_regex = st.text_input("Enter a site name (% wildcard):", key="cookies_site_regex")
        if not site_regex:
            site_regex = "%"

    with col2:
        cookie_name_regex = st.text_input("Enter a cookie name (% wildcard):", key="cookies_name_regex")
        if not cookie_name_regex:
            cookie_name_regex = "%"

    # actually grab our cookies
    df_cookies = utils.get_cookie_df(source_selection, username_selection, browser_selection, site_regex, cookie_name_regex, show_encrypted, show_expired)
    cookie_count = 0
    if df_cookies is not None:
        cookie_count = len(df_cookies)

    col1, col2 = st.columns(2)

    with col1:
        col1.metric("Cookies found", cookie_count)

    with col2:
        # format our cookie dataframe for EditThisCookie download
        if df_cookies is not None and cookie_count > 0:
            df_cookies_download = df_cookies.copy()
            df_cookies_download = df_cookies_download.rename(columns={"expires_utc": "expirationDate"})
            df_cookies_download = df_cookies_download.drop("source", axis=1)
            df_cookies_download = df_cookies_download.drop("username", axis=1)
            df_cookies_download = df_cookies_download.drop("browser", axis=1)
            df_cookies_download = df_cookies_download.drop("unique_db_id", axis=1)
            df_cookies_download = df_cookies_download.drop("notes", axis=1)
            df_cookies_download["hostOnly"] = False
            df_cookies_download["httpOnly"] = False
            df_cookies_download["secure"] = True
            df_cookies_download["session"] = False
            df_cookies_download["sameSite"] = "lax"
            df_cookies_download["storeId"] = "0"
            df_cookies_download["id"] = range(1, len(df_cookies_download) + 1)

            st.write("")
            btn = st.download_button(
                label="Download EditThisCookie JSON",
                data=df_cookies_download.to_json(orient="records", date_format="epoch"),
                file_name="cookies.json",
            )

    if df_cookies is not None and cookie_count > 0:
        gb = GridOptionsBuilder.from_dataframe(df_cookies)
        gb.configure_default_column(groupable=True)
        gb.configure_column("path", hide=True)
        gb.configure_column("unique_db_id", hide=True)

        # set the "notes" column to be editable
        gb.configure_column("notes", editable=True, groupable=True, singleClickEdit=True)

        gb.configure_column("username", width=140)
        gb.configure_column("browser", width=100)
        gb.configure_column("domain", wrapText=True, autoHeight=True)
        gb.configure_column("name", width=180)
        gb.configure_column("value", width=200)
        gb.configure_column("expires_utc", width=150, wrapText=True, autoHeight=True)

        gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=15)

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

        # build and display our grid
        grid = AgGrid(
            df_cookies,
            gridOptions=gb.build(),
            width="100%",
            fit_columns_on_grid_load=False,
            data_return_mode=DataReturnMode.AS_INPUT,
            update_mode=GridUpdateMode.VALUE_CHANGED | GridUpdateMode.SELECTION_CHANGED,
            allow_unsafe_jscode=True,
            columns_auto_size_mode=ColumnsAutoSizeMode.FIT_CONTENTS,
            custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
        )

        for row in grid["selected_rows"]:
            utils.update_notes_table(row["unique_db_id"], "chromium_cookies", authenticated_user, row["notes"])


def build_logins_tab(authenticated_user: str):
    global usernames
    global sources

    col1, col2, col3, col4 = st.columns(4)
    with col3:
        show_encrypted = st_toggle_switch(
            label="Show encrypted logins",
            key="unencrypted_logins_switch",
            default_value=False,
            label_after=False,
        )
    with col4:
        show_blank = st_toggle_switch(label="Show blank logins", key="blank_logins_switch", default_value=False, label_after=False)

    sources = utils.get_unique_sources("chromium_logins")

    if not sources or len(sources) == 0:
        st.error("No Chromium logins data in the database")
        return

    source_selection = st_searchbox(
        search_sources,
        label="Enter a source/computer name to search for:",
        placeholder="Type to search...",
        key="sources_searchbox_logins",
    )

    if not source_selection:
        source_selection = "%"

    usernames = utils.get_usernames_for_source("logins", source_selection)

    col1, col2 = st.columns(2)

    with col1:
        username_selection = st_searchbox(
            search_usernames,
            label="Enter a username to search for:",
            placeholder="Type to search...",
            key="logins_searchbox_usernames",
        )
        if not username_selection:
            username_selection = "%"

    with col2:
        browsers = utils.get_browsers_for_source_username("logins", source_selection, username_selection)
        browser_selection = st.selectbox("Select a browser:", browsers, key="logins_select_browser")
        # set our wildcard if we're searching for all browsers
        if browser_selection == "all":
            browser_selection = "%"

    col1, col2 = st.columns(2)

    with col1:
        site_regex = st.text_input("Enter a site name (% wildcard):", key="logins_site_regex")
        if not site_regex:
            site_regex = "%"
    with col2:
        username_name_regex = st.text_input("Enter a login username (% wildcard):", key="logins_username_regex")
        if not username_name_regex:
            username_name_regex = "%"

    # actually grab our logins
    df_logins = utils.get_login_df(source_selection, username_selection, browser_selection, site_regex, username_name_regex, show_encrypted, show_blank)
    login_count = 0
    if df_logins is not None:
        login_count = len(df_logins)

    col1.metric("Logins found", login_count)

    if df_logins is not None and login_count > 0:
        gb = GridOptionsBuilder.from_dataframe(df_logins)
        gb.configure_default_column(groupable=True)
        gb.configure_column("path", hide=True)
        gb.configure_column("unique_db_id", hide=True)

        # set the "notes" column to be editable
        gb.configure_column("notes", editable=True, groupable=True, singleClickEdit=True)

        gb.configure_column("username", width=150)
        gb.configure_column("browser", width=100)
        gb.configure_column("url", wrapText=True, autoHeight=True)
        gb.configure_column("password", wrapText=True, autoHeight=True)
        gb.configure_column("last_used", width=130, wrapText=True, autoHeight=True)
        gb.configure_column("used", width=120)

        gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=50)

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

        # build and display our grid
        grid = AgGrid(
            df_logins,
            columns_auto_size_mode=ColumnsAutoSizeMode.FIT_CONTENTS,
            gridOptions=gb.build(),
            fit_columns_on_grid_load=True,
            data_return_mode=DataReturnMode.AS_INPUT,
            update_mode=GridUpdateMode.VALUE_CHANGED | GridUpdateMode.SELECTION_CHANGED,
            allow_unsafe_jscode=True,
            custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
        )

        for row in grid["selected_rows"]:
            utils.update_notes_table(row["unique_db_id"], "chromium_logins", authenticated_user, row["notes"])


def build_history_tab(authenticated_user: str):
    global usernames
    global sources
    sources = utils.get_unique_sources("chromium_history")

    if not sources or len(sources) == 0:
        st.error("No Chromium history data in the database")
        return

    source_selection = st_searchbox(
        search_sources,
        label="Enter a source/computer name to search for:",
        placeholder="Type to search...",
        key="sources_searchbox_history",
    )

    if not source_selection:
        source_selection = "%"

    usernames = utils.get_usernames_for_source("history", source_selection)

    col1, col2 = st.columns(2)
    with col1:
        username_selection = st_searchbox(
            search_usernames,
            label="Enter a username to search for:",
            placeholder="Type to search...",
            key="history_searchbox_usernames",
        )
        if not username_selection:
            username_selection = "%"

    with col2:
        browsers = utils.get_browsers_for_source_username("history", source_selection, username_selection)
        browser_selection = st.selectbox("Select a browser:", browsers, key="history_select_browser")
        # set our wildcard if we're searching for all browsers
        if browser_selection == "all":
            browser_selection = "%"

    col1, col2 = st.columns(2)

    with col1:
        site_regex = st.text_input("Enter a site name (% wildcard):", key="history_site_regex")
        if not site_regex:
            site_regex = "%"
    with col2:
        title_regex = st.text_input("Enter a title (% wildcard):", key="history_title_regex")
        if not title_regex:
            title_regex = "%"

    # actually grab our history entries
    df_history = utils.get_history_df(source_selection, username_selection, browser_selection, site_regex, title_regex)
    history_count = 0
    if df_history is not None:
        history_count = len(df_history)

    col1.metric("History entries found", history_count)

    if df_history is not None and history_count > 0:
        gb = GridOptionsBuilder.from_dataframe(df_history)
        gb.configure_default_column(groupable=True)
        gb.configure_column("originating_object_id", hide=True)
        gb.configure_column("unique_db_id", hide=True)

        # set the "notes" column to be editable
        gb.configure_column("notes", editable=True, groupable=True, singleClickEdit=True)

        gb.configure_column("username", width=150)
        gb.configure_column("browser", width=100)
        gb.configure_column("url", wrapText=True, autoHeight=True)
        gb.configure_column("title", wrapText=True, autoHeight=True)
        gb.configure_column("visits", width=40)
        gb.configure_column("last_visit_time", width=140)

        gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=100)

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

        # build and display our grid
        grid = AgGrid(
            df_history,
            gridOptions=gb.build(),
            height="800px",
            fit_columns_on_grid_load=True,
            data_return_mode=DataReturnMode.AS_INPUT,
            update_mode=GridUpdateMode.VALUE_CHANGED | GridUpdateMode.SELECTION_CHANGED,
            allow_unsafe_jscode=True,
            custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
        )

        for row in grid["selected_rows"]:
            utils.update_notes_table(row["unique_db_id"], "chromium_logins", authenticated_user, row["notes"])


def build_downloads_tab(authenticated_user: str):
    global usernames
    global sources

    sources = utils.get_unique_sources("chromium_downloads")

    if not sources or len(sources) == 0:
        st.error("No Chromium downloads data in the database")
        return

    source_selection = st_searchbox(
        search_sources,
        label="Enter a source/computer name to search for:",
        placeholder="Type to search...",
        key="sources_searchbox_downloads",
    )

    if not source_selection:
        source_selection = "%"

    usernames = utils.get_usernames_for_source("downloads", source_selection)

    col1, col2 = st.columns(2)
    with col1:
        username_selection = st_searchbox(
            search_usernames,
            label="Enter a username to search for:",
            placeholder="Type to search...",
            key="downloads_searchbox_usernames",
        )
        if not username_selection:
            username_selection = "%"

    with col2:
        browsers = utils.get_browsers_for_source_username("downloads", source_selection, username_selection)
        browser_selection = st.selectbox("Select a browser:", browsers, key="downloads_select_browser")
        # set our wildcard if we're searching for all browsers
        if browser_selection == "all":
            browser_selection = "%"

    col1, col2 = st.columns(2)

    with col1:
        site_regex = st.text_input("Enter a site name (% wildcard):", key="downloads_site_regex")
        if not site_regex:
            site_regex = "%"
    with col2:
        path_regex = st.text_input("Enter a download file/path name:", key="downloads_path_regex")
        if not path_regex:
            path_regex = "%"

    # actually grab our download entries
    df_download = utils.get_download_df(source_selection, username_selection, browser_selection, site_regex, path_regex)
    download_count = 0
    if df_download is not None:
        download_count = len(df_download)

    col1.metric("Downloads found", download_count)

    if df_download is not None and download_count > 0:
        gb = GridOptionsBuilder.from_dataframe(df_download)
        gb.configure_default_column(groupable=True)
        gb.configure_column("path", hide=True)
        gb.configure_column("danger_type", hide=True)
        gb.configure_column("unique_db_id", hide=True)

        # set the "notes" column to be editable
        gb.configure_column("notes", editable=True, groupable=True, singleClickEdit=True)

        gb.configure_column("username", width=150)
        gb.configure_column("browser", width=80)
        gb.configure_column("url", wrapText=True, autoHeight=True)
        gb.configure_column("download_path", wrapText=True, autoHeight=True)
        gb.configure_column("timestamp", width=110, wrapText=True, autoHeight=True)
        gb.configure_column("danger_type", width=130, wrapText=True, autoHeight=True)

        gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=15)

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

        # build and display our grid
        grid = AgGrid(
            df_download,
            gridOptions=gb.build(),
            width="100%",
            fit_columns_on_grid_load=True,
            data_return_mode=DataReturnMode.AS_INPUT,
            update_mode=GridUpdateMode.VALUE_CHANGED | GridUpdateMode.SELECTION_CHANGED,
            allow_unsafe_jscode=True,
            columns_auto_size_mode=ColumnsAutoSizeMode.FIT_CONTENTS,
            custom_css={"#gridToolBar": {"padding-bottom": "0px !important"}},  # See https://github.com/PablocFonseca/streamlit-aggrid/issues/231#issuecomment-1696943095
        )

        for row in grid["selected_rows"]:
            utils.update_notes_table(row["unique_db_id"], "chromium_downloads", authenticated_user, row["notes"])


def build_page(authenticated_user: str):
    build_about_bar()

    query_params = get_search_filters()
    chosen_tab = query_params["tab"][0]

    if chosen_tab == "cookies":
        build_cookies_tab(authenticated_user)

    if chosen_tab == "logins":
        build_logins_tab(authenticated_user)

    if chosen_tab == "history":
        build_history_tab(authenticated_user)

    if chosen_tab == "downloads":
        build_downloads_tab(authenticated_user)


utils.render_nemesis_page(build_page)
