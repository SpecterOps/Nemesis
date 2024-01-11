# Standard Libraries
import datetime
import os
import re
import time
import uuid
from typing import List, Tuple

# 3rd Party Libraries
import auth
import pandas as pd
import psycopg
import requests
import streamlit as st
from elasticsearch import Elasticsearch
from sqlalchemy import create_engine
from sqlalchemy import text as sql_text
from streamlit_extras.app_logo import add_logo

# pull in and check all of our required environment variables
WAIT_TIMEOUT = 5
POSTGRES_CONNECTION_URI = os.environ.get("POSTGRES_CONNECTION_URI") or ""
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL") or ""
ELASTICSEARCH_USER = os.environ.get("ELASTICSEARCH_USER") or ""
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD") or ""
DASHBOARD_USER = os.environ.get("DASHBOARD_USER")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")
NLP_URL = os.environ.get("NLP_URL")
NEMESIS_API_URL = "http://enrichment-webapi:9910/"

if not all(
    var is not None and var != ""
    for var in (
        POSTGRES_CONNECTION_URI,
        ELASTICSEARCH_URL,
        ELASTICSEARCH_USER,
        ELASTICSEARCH_PASSWORD,
        DASHBOARD_USER,
        DASHBOARD_PASSWORD,
        NLP_URL,
    )
):
    raise Exception("Missing environment variables. Please check your .env file.")

engine = create_engine(POSTGRES_CONNECTION_URI)


######################################################
#
# NLP helpers
#
######################################################


def semantic_search(search_phrase: str, num_results: int = 4) -> dict:
    """
    Calls {NLP_URL}/semantic_search to extract password candidates from a plaintext document.
    """

    try:
        data = {"search_phrase": search_phrase, "num_results": num_results}
        url = f"{NLP_URL}semantic_search"
        result = requests.post(url, json=data)
        return result.json()
    except Exception as e:
        return {"error": f"Error calling semantic_search with search_phrase '{search_phrase}' : {e}"}


######################################################
#
# Postgres helpers (mostly for the Chromium page)
#
######################################################


def get_unique_sources(table: str):
    """
    Given a table name return all of the unique sources for that table.
    """
    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT DISTINCT source FROM nemesis.{table}")
                return [x[0] for x in cur.fetchall()]
    except Exception as e:
        st.error(f"Exception querying the database: {e}")


def get_unique_projects(table: str):
    """
    Given a table name return all of the unique project for that table.
    """
    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT DISTINCT project_id FROM nemesis.{table}")
                return [x[0] for x in cur.fetchall()]
    except Exception as e:
        st.error(f"Exception querying the database: {e}")


def get_usernames_for_source(table: str, source: str) -> List[str]:
    """
    Given a table name (cookies, logins, history, downloads) and source term
    return all of the unique usernames for that source/table.
    """
    with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT DISTINCT username FROM nemesis.chromium_{table} WHERE source ILIKE %s", (source,))
            return [x[0] for x in cur.fetchall()]


def get_browsers_for_source_username(table: str, source: str, username: str) -> List[str]:
    """
    Given a table name (cookies, logins, history, downloads), source term, and
    username return all of the unique browsers for that combination.
    """
    with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT DISTINCT browser FROM nemesis.chromium_{table} WHERE source ILIKE %s AND username ILIKE %s", (source, username))
            return ["all"] + [x[0] for x in cur.fetchall()]


def get_cookie_df(source: str, username: str, browser: str, site: str, name: str, show_encrypted: bool, show_expired: bool) -> pd.DataFrame:
    """Return a cookies dataframe based on the query parameters."""

    query = """
SELECT
    chromium_cookies.source AS source,
    chromium_cookies.username AS username,
    chromium_cookies.browser AS browser,
    chromium_cookies.host_key AS domain,
    chromium_cookies.name AS name,
    chromium_cookies.path AS path,
    chromium_cookies.value_dec AS value,
    chromium_cookies.expires_utc AS expires_utc,
    chromium_cookies.unique_db_id::varchar AS unique_db_id,
    chromium_cookies.user_data_directory AS user_data_directory,
    notes.value as notes

FROM chromium_cookies

LEFT JOIN notes
ON chromium_cookies.unique_db_id = notes.unique_db_id

WHERE
    source ILIKE :source
    AND username ILIKE :username
    AND browser ILIKE :browser
    AND host_key ILIKE :host_key
    AND name ILIKE :name
"""

    if not show_encrypted:
        query += "\n    AND is_decrypted = True"

    if not show_expired:
        query += "\n    AND expires_utc > now() at time zone 'utc'"

    query += "\n    ORDER BY chromium_cookies.timestamp DESC"

    try:
        with engine.connect() as conn:
            params = {"source": source, "username": username, "browser": browser, "host_key": site, "name": name}
            return pd.read_sql_query(sql_text(query), conn, params=params)
    except Exception as e:
        st.error(f"Error retrieving `chromium_cookies` from the database: {e}", icon="🚨")
        print(f"Exception: {e}")


def get_login_df(source: str, username: str, browser: str, url: str, login_username: str, show_encrypted: bool, show_blank: bool) -> pd.DataFrame:
    """Return a logins dataframe based on the query parameters."""

    query = """
SELECT
    chromium_logins.source AS source,
    chromium_logins.username AS username,
    chromium_logins.browser AS browser,
    chromium_logins.origin_url AS url,
    chromium_logins.username_value AS username_value,
    chromium_logins.password_value_dec AS password,
    chromium_logins.date_last_used AS last_used,
    chromium_logins.is_decrypted AS is_decrypted,
    chromium_logins.times_used AS used,
    chromium_logins.unique_db_id::varchar AS unique_db_id,
    notes.value as notes

FROM chromium_logins

LEFT JOIN notes
ON chromium_logins.unique_db_id = notes.unique_db_id

WHERE
    source ILIKE :source
    AND username ILIKE :username
    AND browser ILIKE :browser
    AND origin_url ILIKE :url
    AND username_value ILIKE :login_username
"""

    if not show_encrypted:
        query += "\n    AND is_decrypted = True"
    if show_blank:
        query += "\n    AND length(password_value_dec) > 0"

    query += "\n    ORDER BY chromium_logins.timestamp DESC"

    try:
        with engine.connect() as conn:
            params = {"source": source, "username": username, "browser": browser, "url": url, "login_username": login_username}
            return pd.read_sql_query(sql_text(query), conn, params=params)
    except Exception as e:
        st.error(f"Error retrieving `chromium_logins` from the database: {e}", icon="🚨")


def get_history_df(source: str, username: str, browser: str, url: str, title: str):
    """Return a history dataframe based on the query parameters."""

    query = """
SELECT
    chromium_history.source AS source,
    chromium_history.originating_object_id::varchar AS originating_object_id,
    chromium_history.username AS username,
    chromium_history.browser AS browser,
    chromium_history.url AS url,
    chromium_history.title AS title,
    chromium_history.visit_count AS visits,
    chromium_history.last_visit_time AS last_visit_time,
    chromium_history.unique_db_id::varchar AS unique_db_id,
    notes.value as notes

FROM chromium_history

LEFT JOIN notes
ON chromium_history.unique_db_id = notes.unique_db_id

WHERE
    chromium_history.source ILIKE :source
    AND chromium_history.username ILIKE :username
    AND chromium_history.browser ILIKE :browser
    AND chromium_history.url ILIKE :url
    AND chromium_history.title ILIKE :title

ORDER BY chromium_history.timestamp DESC
"""
    try:
        with engine.connect() as conn:
            params = {"source": source, "username": username, "browser": browser, "url": url, "title": title}
            return pd.read_sql_query(sql_text(query), conn, params=params)
    except Exception as e:
        st.error(f"Error retrieving `chromium_history` from the database: {e}", icon="🚨")


def get_download_df(source: str, username: str, browser: str, url: str, download_path: str):
    """Return a downloads dataframe based on the query parameters."""

    query = """
SELECT
    chromium_downloads.source AS source,
    chromium_downloads.username AS username,
    chromium_downloads.browser AS browser,
    chromium_downloads.url AS url,
    chromium_downloads.download_path as download_path,
    chromium_downloads.end_time as timestamp,
    chromium_downloads.danger_type as danger_type,
    chromium_downloads.unique_db_id::varchar AS unique_db_id, notes.value as notes

FROM chromium_downloads

LEFT JOIN notes
ON chromium_downloads.unique_db_id = notes.unique_db_id

WHERE
    chromium_downloads.source ILIKE :source
    AND chromium_downloads.username ILIKE :username
    AND chromium_downloads.browser ILIKE :browser
    AND chromium_downloads.url ILIKE :url
    AND chromium_downloads.download_path ILIKE :download_path

ORDER BY chromium_downloads.timestamp DESC
"""
    try:
        with engine.connect() as conn:
            params = {"source": source, "username": username, "browser": browser, "url": url, "download_path": download_path}
            return pd.read_sql_query(sql_text(query), conn, params=params)
    except Exception as e:
        st.error(f"Error retrieving `chromium_downloads` from the database: {e}", icon="🚨")


@st.cache_data(ttl=1000, show_spinner="Fetching fresh data from the database...")
def get_masterkeys() -> pd.DataFrame:
    """Performs the main database query for masterkeys so the data can be cached on reruns."""

    query = """
        SELECT dpapi_masterkeys.source, dpapi_masterkeys.username, dpapi_masterkeys.user_sid, dpapi_masterkeys.timestamp, dpapi_masterkeys.type, dpapi_masterkeys.masterkey_guid::text, dpapi_masterkeys.is_decrypted, COUNT(dpapi_blobs.unique_db_id) AS dpapi_blobs, COUNT(chromium_state_files.unique_db_id) AS state_files

        from dpapi_masterkeys

        LEFT JOIN dpapi_blobs
        ON dpapi_masterkeys.masterkey_guid = dpapi_blobs.masterkey_guid

        LEFT JOIN chromium_state_files
        ON dpapi_masterkeys.masterkey_guid = chromium_state_files.masterkey_guid

        GROUP BY dpapi_masterkeys.masterkey_guid
    """

    try:
        with engine.connect() as conn:
            # read the query directly into the dataframe and return it
            df = pd.read_sql_query(sql_text(query), conn)

            # st.session_state["df"] is set to the database output on each non-cached run
            st.session_state["df_loaded"] = True
            print("[*] Retrieved fresh data from the database!")
            return df
    except Exception as e:
        st.error(f"Error retrieving dpapi_masterkeys from the database: {e}", icon="🚨")


@st.cache_data(ttl=1000, show_spinner="Fetching fresh data from the database...")
def get_password_data() -> pd.DataFrame:
    """Performs the main database query for passwords so the data can be cached on reruns."""

    # query the `nemesis.authentication_data` table for entries of type "password"
    #   we need a left outer join here with the `nemesis.triage` table
    query = """
        SELECT authentication_data.unique_db_id::varchar, authentication_data.agent_id, authentication_data.timestamp, authentication_data.username, authentication_data.data, authentication_data.uri as url, authentication_data.source, authentication_data.originating_object_id::varchar as object_id, triage.value as triage, notes.value as notes

        FROM authentication_data

        LEFT JOIN triage
        ON authentication_data.unique_db_id = triage.unique_db_id

        LEFT JOIN notes
        ON authentication_data.unique_db_id = notes.unique_db_id

        WHERE authentication_data.type = 'password'
    """

    try:
        with engine.connect() as conn:
            # read the query directly into the dataframe and return it
            df = pd.read_sql_query(sql_text(query), conn)

            # st.session_state["df"] is set to the database output on each non-cached run
            st.session_state["df_loaded"] = True
            print("[*] Retrieved fresh data from the database!")
            return df
    except Exception as e:
        st.error(f"Error retrieving authentication_data from the database: {e}", icon="🚨")


def update_triage_table(unique_db_id: str, table_name: str, operator: str, triage_value: str, originating_object_id: str = "") -> None:
    """
    Updates the triage table with the triage value for the specified unique_db_id.

    If an originating_object_id is passed, that file object is updated as well.
    """
    try:
        # update the triage value in the Postgres `nemesis.triage` table for this unique_db_id
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            triage_value = triage_value.lower()
            print(f"[*] Changing triage for unique_db_id object '{unique_db_id}' to value '{triage_value}'")

            with conn.cursor() as cur:
                # get the expiration of the associated object so we can use it for the triage table update
                cur.execute(f"SELECT expiration FROM nemesis.{table_name} WHERE unique_db_id = '{unique_db_id}'")
                expiration = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO nemesis.triage (unique_db_id, table_name, operator, value, expiration, modification_time)
                    VALUES (%(unique_db_id)s, %(table_name)s, %(operator)s, %(value)s, %(expiration)s, now() at time zone 'utc')
                    ON CONFLICT (unique_db_id)
                    DO UPDATE SET value = %(value)s, modification_time = now() at time zone 'utc'
                    """,
                    {"unique_db_id": unique_db_id, "table_name": table_name, "operator": operator, "value": triage_value, "expiration": expiration},
                )

                # if there's a linked originating object, update that as well
                if originating_object_id:
                    cur.execute(
                        """
                        SELECT unique_db_id::varchar
                        FROM nemesis.file_data_enriched
                        WHERE object_id = %s
                        """,
                        (originating_object_id,),
                    )
                    output = cur.fetchone()
                    if output:
                        print(f"[*] Changing originating_object_id object '{originating_object_id}' to triage value '{triage_value}'")
                        cur.execute(
                            """
                            INSERT INTO nemesis.triage (unique_db_id, table_name, operator, value, expiration, modification_time)
                            VALUES (%(unique_db_id)s, %(table_name)s, %(operator)s, %(value)s, %(expiration)s, now() at time zone 'utc')
                            ON CONFLICT (unique_db_id)
                            DO UPDATE SET value = %(value)s, modification_time = now() at time zone 'utc'
                            """,
                            {"unique_db_id": unique_db_id, "table_name": "file_data_enriched", "operator": operator, "value": triage_value, "expiration": expiration},
                        )
            conn.commit()

    except Exception as e:
        st.error(f"Exception saving data to the database: {e}", icon="🚨")


def update_notes_table(unique_db_id: str, table_name: str, operator: str, notes_value: str) -> None:
    """
    Updates the notes table with the notes value for the specified unique_db_id.
    """
    try:
        # update the triage value in the Postgres `nemesis.triage` table for this unique_db_id
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            print(f"[*] Changing notes for unique_db_id object '{unique_db_id}' to value '{notes_value}'")

            with conn.cursor() as cur:
                # get the expiration of the associated object so we can use it for the notes table update
                cur.execute(f"SELECT expiration FROM nemesis.{table_name} WHERE unique_db_id = '{unique_db_id}'")
                expiration = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO nemesis.notes (unique_db_id, table_name, operator, value, expiration, modification_time)
                    VALUES (%(unique_db_id)s, %(table_name)s, %(operator)s, %(value)s, %(expiration)s, now() at time zone 'utc')
                    ON CONFLICT (unique_db_id)
                    DO UPDATE SET value = %(value)s, modification_time = now() at time zone 'utc'
                    """,
                    {"unique_db_id": unique_db_id, "table_name": table_name, "operator": operator, "value": notes_value, "expiration": expiration},
                )

            conn.commit()

    except Exception as e:
        st.error(f"Exception saving data to the database: {e}", icon="🚨")


def postgres_count_entries(table_name: str) -> int:
    """
    Given a table name, returns the total number of entries.
    """
    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM nemesis.{table_name}")
                return cur.fetchone()[0]
    except Exception as e:
        return -1


def postgres_count_triaged_files() -> int:
    """
    Returns the number of triaged files.
    """
    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM nemesis.triage WHERE \"table_name\" = 'file_data_enriched'")
                return cur.fetchone()[0]
    except Exception as e:
        return -1


def postgres_count_dpapi_blobs(show_all=True, show_dec=True, masterkey_guid=""):
    """
    Count the number of dpapi_blobs matching specific criteria.
    """

    query = "SELECT COUNT(*) FROM nemesis.dpapi_blobs "

    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                if not show_all:
                    # if this section isn't hit, all enc/dec are shown
                    if show_dec:
                        # only show decrypted
                        query += "WHERE is_decrypted = True "
                    else:
                        # only show encrypted
                        query += "WHERE is_decrypted = False "
                    if masterkey_guid != "":
                        query += f"WHERE masterkey_guid = '{masterkey_guid}'"
                elif masterkey_guid != "":
                    query += f"WHERE masterkey_guid = '{masterkey_guid}'"
                cur.execute(query)
                return cur.fetchone()[0]
    except Exception as e:
        print(f"Exception: {e}")
        return -1


def postgres_count_state_files(show_all=True, show_dec=True, masterkey_guid=""):
    """
    Count the number of chromium_state_files matching specific criteria.
    """

    query = "SELECT COUNT(*) FROM nemesis.chromium_state_files "

    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                if not show_all:
                    # if this section isn't hit, all enc/dec are shown
                    if show_dec:
                        # only show decrypted
                        query += "WHERE is_decrypted = True "
                    else:
                        # only show encrypted
                        query += "WHERE is_decrypted = False "
                    if masterkey_guid != "":
                        query += f"WHERE masterkey_guid = '{masterkey_guid}'"
                elif masterkey_guid != "":
                    query += f"WHERE masterkey_guid = '{masterkey_guid}'"
                cur.execute(query)
                return cur.fetchone()[0]
    except Exception as e:
        print(f"Exception: {e}")
        return -1


def postgres_count_masterkeys(show_all=True, show_dec=True, key_type=""):
    """
    Count the number of masterkeys matching specific criteria.

    Types: domain_user, local_user, machine
    """

    query = "SELECT COUNT(*) FROM nemesis.dpapi_masterkeys "

    try:
        with psycopg.connect(POSTGRES_CONNECTION_URI) as conn:
            with conn.cursor() as cur:
                if not show_all:
                    # if this section isn't hit, all enc/dec are shown
                    if show_dec:
                        # only show decrypted
                        query += "WHERE is_decrypted = True "
                    else:
                        # only show encrypted
                        query += "WHERE is_decrypted = False "
                    if key_type:
                        query += f"AND type = '{key_type}'"
                elif key_type:
                    query += f"WHERE type = '{key_type}'"
                cur.execute(query)
                return cur.fetchone()[0]
    except Exception as e:
        print(f"Exception: {e}")
        return -1


def get_file_information(object_id: str):
    """Gets information from Postgres about a specific file."""

    if not re.match(r"^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$", object_id):
        raise Exception(f"object_id '{object_id}' supplied to get_file_information() is not a proper UUID")

    try:
        with engine.connect() as conn:
            params = {
                "object_id": object_id,
            }

            query = """
                    SELECT  file_data_enriched.project_id as project_id,
                            file_data_enriched.source as source,
                            file_data_enriched.timestamp as timestamp,
                            file_data_enriched.unique_db_id::varchar,
                            file_data_enriched.agent_id as agent_id,
                            file_data_enriched.object_id::varchar as object_id,
                            file_data_enriched.path as path,
                            file_data_enriched.name as name,
                            file_data_enriched.size as size,
                            file_data_enriched.md5 as md5,
                            file_data_enriched.sha1 as sha1,
                            file_data_enriched.sha256 as sha256,
                            file_data_enriched.nemesis_file_type as nemesis_file_type,
                            file_data_enriched.magic_type as magic_type,
                            file_data_enriched.converted_pdf_id::varchar as converted_pdf_id,
                            file_data_enriched.extracted_plaintext_id::varchar as extracted_plaintext_id,
                            file_data_enriched.extracted_source_id::varchar as extracted_source_id,
                            file_data_enriched.tags as tags,
                            file_data_enriched.originating_object_id as originating_object_id,
                            triage.value as triage,
                            triage.unique_db_id as triage_unique_db_id,
                            notes.value as notes

                    FROM file_data_enriched

                    LEFT JOIN triage
                        ON file_data_enriched.unique_db_id = triage.unique_db_id

                    LEFT JOIN notes
                        ON file_data_enriched.unique_db_id = notes.unique_db_id

                    WHERE object_id = :object_id
                """

            df = pd.read_sql_query(sql_text(query), conn, params=params)
            if len(df) == 0:
                st.error(f"object_id '{object_id}' not found")
            elif len(df) == 1:
                return df.iloc[0]
            else:
                st.error(f"Too many results for object_id '{object_id}' : {len(df)}", icon="🚨")

    except Exception as e:
        st.error(f"Error retrieving `file_data_enriched` from the database: {e}", icon="🚨")
        return None


def postgres_file_search(
    startdate: datetime.datetime,
    enddate: datetime.datetime,
    from_i: int = 0,
    size: int = 8,
    source: str = "%",
    project_id: str = "%",
    file_hash: str = "",
    path_pattern: str = "",
    notes_pattern: str = "",
    tags: List[str] = [],
    show_triaged: bool = False,
    show_archive_originated: bool = False,
    order_desc_timestamp: bool = False,
) -> Tuple:
    """
    Searches the nemesis.file_data_enriched table for paginated results given
    the supplied search parameters.
    """

    query = """SELECT
    file_data_enriched.project_id as project_id,
    file_data_enriched.source as source,
    file_data_enriched.timestamp as "timestamp",
    file_data_enriched.unique_db_id::varchar,
    file_data_enriched.agent_id as agent_id,
    file_data_enriched.object_id::varchar as object_id,
    file_data_enriched.path as path,
    file_data_enriched.name as name,
    file_data_enriched.size as size,
    file_data_enriched.md5 as md5,
    file_data_enriched.sha1 as sha1,
    file_data_enriched.sha256 as sha256,
    file_data_enriched.nemesis_file_type as nemesis_file_type,
    file_data_enriched.magic_type as magic_type,
    file_data_enriched.converted_pdf_id::varchar as converted_pdf_id,
    file_data_enriched.extracted_plaintext_id::varchar as extracted_plaintext_id,
    file_data_enriched.extracted_source_id::varchar as extracted_source_id,
    file_data_enriched.tags as tags,
    file_data_enriched.originating_object_id as originating_object_id,
    triage.value as triage,
    triage.unique_db_id as triage_unique_db_id,
    notes.value as notes

FROM file_data_enriched

LEFT JOIN triage
    ON file_data_enriched.unique_db_id = triage.unique_db_id

LEFT JOIN notes
    ON file_data_enriched.unique_db_id = notes.unique_db_id
    AND notes.value ILIKE :notes

WHERE source ILIKE :source
    AND project_id ILIKE :project_id
    AND "timestamp" >= :startdate
    AND "timestamp" <= :enddate
"""

    if path_pattern:
        query += "\n    AND path ILIKE :path"

    if file_hash:
        query += "\n    AND (md5 ILIKE :md5 OR sha1 ILIKE :sha1 OR sha256 ILIKE :sha256)"

    if tags:
        for i in range(len(tags)):
            query += f"\n    AND :tag_{i} = ANY(file_data_enriched.tags)"
    if not show_triaged:
        query += "\n    AND (triage.value IS NULL OR triage.value = 'unknown')"
    if not show_archive_originated:
        query += "\n    AND originating_object_id = '00000000-0000-0000-0000-000000000000'"
    if notes_pattern:
        query += "\n    AND notes.value ILIKE :notes"

    if order_desc_timestamp:
        query += '\n    ORDER BY "timestamp" DESC'

    # Build the COUNT query *before* any pagination
    count_query = f"SELECT COUNT(*) FROM ({query}) AS s"

    # add in the pagination
    query += "\n        LIMIT :size OFFSET :from_i"

    try:
        with engine.connect() as conn:
            params = {
                "startdate": startdate,
                "enddate": enddate,
                "source": source,
                "project_id": project_id,
                "path": path_pattern,
                "notes": f"%{notes_pattern}%",
                "md5": file_hash,
                "sha1": file_hash,
                "sha256": file_hash,
                "size": size,
                "from_i": from_i,
            }

            # have to dynamically build this because of how we have to search
            #   through arrays in postgres
            for i in range(len(tags)):
                params[f"tag_{i}"] = tags[i]

            total_hits = pd.read_sql_query(sql_text(count_query), conn, params=params)["count"][0].item()
            df = pd.read_sql_query(sql_text(query), conn, params=params)
            return (total_hits, df)

    except Exception as e:
        st.error(f"Error retrieving `file_data_enriched` from the database: {e}", icon="🚨")
        return (None, None)


######################################################
#
# Common Authentication/Header Helpers
#
######################################################
def header() -> None:
    pass


def render_nemesis_page(render_func):
    """Writes out the logo/auth header/etc. for all pages."""

    if "ENVIRONMENT" in os.environ and os.environ["ENVIRONMENT"].lower() == "development":
        page_title = "Nemesis (DEV)"
    else:
        page_title = "Nemesis"

    if "ASSESSMENT_ID" in os.environ:
        page_title += f" - {os.environ['ASSESSMENT_ID']}"

    st.set_page_config(
        layout="wide",
        page_title=page_title,
        page_icon="img/favicon.png",
        menu_items={"Get Help": "https://www.github.com/SpecterOps/Nemesis"},
    )

    st.markdown(
        unsafe_allow_html=True,
        body="""
<style>
    .block-container {
            padding-top: 0rem;
            padding-bottom: 10rem;
            padding-left: 5rem;
            padding-right: 5rem;
        }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""",
    )

    auth.authenticate(render_func)

    add_logo("./img/logo.png", height=160)


######################################################
#
# Elasticsearch Helpers
#
######################################################


def simplify_es_text_result(result: dict) -> dict:
    """Simplifies an elastic result into the three parts we want to use."""
    res = result["_source"]
    res["url"] = result["_id"]
    # join list of highlights into a sentence
    res["highlights"] = "...".join(result["highlight"]["text"])
    return res


def wait_for_elasticsearch():
    """
    Wait for a connection to be established with Nemesis' Elasticsearch container,
    and return the es_client object when a connection is established.
    """

    while True:
        try:
            es_client = Elasticsearch(ELASTICSEARCH_URL, basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD), verify_certs=False)
            es_client.info()
            return es_client
        except Exception:
            print(
                "Encountered an exception while trying to connect to Elasticsearch %s, trying again in %s seconds...",
                ELASTICSEARCH_URL,
                WAIT_TIMEOUT,
            )
            time.sleep(WAIT_TIMEOUT)
            continue


def get_elastic_total_indexed_documents(index_name="file_data_plaintext", query={}) -> int:
    """
    Returns the total number of documents indexed in the specified index.
    """
    try:
        es_client = wait_for_elasticsearch()
        if query:
            return es_client.count(index=index_name, query=query)["count"]
        else:
            return es_client.count(index=index_name)["count"]
    except Exception as e:
        return 0


def elastic_file_search(object_id: str) -> dict:
    """
    Searches the 'file_data_enriched' index in Elasticsearch for
    the matching document, returning all fields.
    """
    try:
        es_client = wait_for_elasticsearch()
        query = {"term": {"objectId.keyword": object_id}}
        return es_client.search(index="file_data_enriched", query=query)
    except Exception as e:
        if "index_not_found_exception" in f"{e}":
            st.error("Elastic index 'file_data_enriched' doesn't yet exist!", icon="🚨")
        else:
            st.error(f"Exception querying Elastic: {e}", icon="🚨")
        return {}


def elastic_text_search(search_term: str, from_i: int, size: int) -> dict:
    """
    Searches the 'file_data_plaintext' index in Elasticsearch for
    the supplied search term, paginating results based on the
    from_i and size.
    """
    try:
        es_client = wait_for_elasticsearch()
        query = {
            # "match": {"text": search_term}
            "wildcard": {"text": {"value": search_term}}
        }
        highlight = {"pre_tags": [""], "post_tags": [""], "fields": {"text": {}}}
        fields = [
            "_id",
            "originatingObjectPath",
            "originatingObjectURL",
            "originatingObjectId",
            "originatingObjectConvertedPdfUrl",
            "wordCount",
            "metadata.source",
        ]
        result = es_client.search(index="file_data_plaintext", query=query, highlight=highlight, from_=from_i, size=size, source_includes=fields)
        return result
    except Exception as e:
        if "index_not_found_exception" in f"{e}":
            st.error("Elastic index 'file_data_plaintext' doesn't yet exist - no text data has been extracted yet!", icon="🚨")
        else:
            st.error(f"Exception querying Elastic: {e}", icon="🚨")
        return None


def elastic_sourcecode_search(search_term: str, from_i: int, size: int) -> dict:
    """
    Searches the 'file_data_sourcecode' index in Elasticsearch for
    the supplied search term, paginating results based on the
    from_i and size.
    """
    try:
        es_client = wait_for_elasticsearch()
        query = {
            #"match": {"text": search_term}
            "wildcard": {"text": {"value": search_term}}
        }
        highlight = {"pre_tags": [""], "post_tags": [""], "fields": {"text": {}}}
        fields = [
            "_id",
            "downloadURL",
            "fileObjectURL",
            "extension",
            "language",
            "name",
            "path",
            "size",
            "metadata.source",
            "objectId",
        ]
        return es_client.search(index="file_data_sourcecode", query=query, highlight=highlight, from_=from_i, size=size, source_includes=fields)
    except Exception as e:
        if "index_not_found_exception" in f"{e}":
            st.error("Elastic index 'file_data_sourcecode' doesn't yet exist - no source code files have been downloaded yet!", icon="🚨")
        else:
            st.error(f"Exception querying Elastic: {e}", icon="🚨")
        return {}


def elastic_np_search(from_i: int, size: int) -> dict:
    """
    Searches the 'file_data_enriched' index in Elasticsearch for
    any files that have NoseyParker results, paginating results based
    on the from_i and size.
    """
    try:
        es_client = wait_for_elasticsearch()
        query = {"exists": {"field": "noseyparker"}}
        fields = ["objectId", "name", "magicType", "path", "nemesisFileType", "hashes.sha1", "metadata.source", "noseyparker"]
        return es_client.search(index="file_data_enriched", query=query, from_=from_i, size=size, source_includes=fields)
    except Exception as e:
        if "index_not_found_exception" in f"{e}":
            st.error("Elastic index 'file_data_enriched' doesn't yet exist - no files have been processed yet!", icon="🚨")
        else:
            st.error(f"Exception querying Elastic: {e}", icon="🚨")
        return {}


######################################################
#
# Misc. Helpers
#
######################################################


def is_uuid(str_uuid: str):
    try:
        uuid.UUID(str_uuid)
        return True
    except:
        return False


def reorder_archive_file_listing(file_listing):
    """
    Reorders a file listing for an archive into a nested dict format.
    """

    total_entries = {}
    for entry in file_listing:
        path = entry["name"]
        path_parts = [p for p in path.replace('\\', '/').split('/') if p]
        num_paths = len(path_parts)
        is_file = True if "uncompressSize" in entry else False
        lastModified = entry["lastModified"] if "lastModified" in entry else ""
        current_entry = None

        for i in range(num_paths):

            # handle the first entry in the path list
            if i == 0:
                if is_file and (i == (num_paths - 1)):
                    uncompressSize = entry["uncompressSize"]
                    temp = f"{path_parts[i]} ({lastModified} - {uncompressSize} bytes)"
                    total_entries[temp] = "file"
                else:
                    path_part = f"{path_parts[i]}/"
                    if path_part not in total_entries:
                        total_entries[path_part] = {}
                    current_entry = total_entries[path_part]
            # handle the last entry in the path list
            elif i == num_paths - 1:
                if is_file:
                    uncompressSize = entry["uncompressSize"]
                    # path_part = path_parts[i]
                    temp = f"{path_parts[i]} ({lastModified} - {uncompressSize} bytes)"
                    current_entry[temp] = "file"
                else:
                    path_part = f"{path_parts[i]}/"
                    current_entry[path_part] = {}
            # handle middle folder entries
            else:
                path_part = f"{path_parts[i]}/"
                if path_part not in current_entry:
                    current_entry[path_part] = {}
                current_entry = current_entry[path_part]

    return total_entries


def get_single_valued_param(name: str) -> None | str:
    """
    Obtains the value of a URL parameter. Ensures that the URL parameter only has a single value.
    If the URL parameter does not exist, the return value is None
    """
    params = st.query_params

    if name not in params:
        return None

    if len(params[name]) != 1:
        raise Exception(f"More than one value was provided for the parameter '{name}'")

    object_id = params[name][0]
    return object_id


def get_monaco_languages() -> List[str]:
    """
    All languages supported by Monaco.

    Ref: https://github.com/microsoft/monaco-editor/tree/d8144cfa0eb66cf9d3cc0507df1ad33bc8fc65c5/src/basic-languages
    """
    return ["plaintext", "abap", "aes", "apex", "azcli", "bat", "bicep", "c", "csv", "cameligo", "clojure", "coffeescript",
            "cpp", "csharp", "csp", "css", "cypher", "dart", "dockerfile", "ecl", "elixir", "flow9",
            "freemarker2", "freemarker2.tag-angle.interpolation-bracket", "freemarker2.tag-angle.interpolation-dollar",
            "freemarker2.tag-auto.interpolation-bracket", "freemarker2.tag-auto.interpolation-dollar",
            "freemarker2.tag-bracket.interpolation-bracket", "freemarker2.tag-bracket.interpolation-dollar", "fsharp",
            "go", "graphql", "handlebars", "hcl", "html", "ini", "java", "javascript", "julia", "kotlin", "less", "lexon",
            "liquid", "lua", "m3", "markdown", "mdx", "mips", "msdax", "mysql", "objective-c", "pascal", "pascaligo",
            "perl", "pgsql", "php", "pla", "postiats", "powerquery", "powershell", "proto", "pug", "python", "qsharp", "r",
            "razor", "redis", "redshift", "restructuredtext", "ruby", "rust", "sb", "scala", "scheme", "scss", "shell",
            "sol", "sparql", "sql", "st", "swift", "systemverilog", "tcl", "twig", "typescript", "vb", "verilog", "wgsl",
            "xml", "yaml"]


def map_extension_to_monaco_language(extension: str) -> str:
    """
    Maps a file extension to a source code language for Monaco.

    Ref: https://github.com/microsoft/monaco-editor/tree/d8144cfa0eb66cf9d3cc0507df1ad33bc8fc65c5/src/basic-languages

        $mappings = gci *contribution.ts -Recurse | gc | select-string -Pattern "\tid: " -Context 0,1 | % {
            $match = $_
            $lang = $match.Line.split("'")[1]
            $ext = $match.Context.PostContext.split("'") | ?{$_.startswith(".")}
            [PSCustomObject]@{
                language = $lang
                extension = $ext
            }
        }

        foreach($mapping in $mappings) {
            $lang = $mapping.language.tolower()
            foreach($ext in $mapping.extension) {
                $ext = $ext.trim(".").tolower()
                Write-Host "        `"$ext`": `"$lang`","
            }
        }

    swift and xml done manually (exceptions)
    """

    ext_to_lang_mappings = {
        "abap": "abap",
        "ascx": "xml",
        "cls": "apex",
        "azcli": "azcli",
        "bat": "bat",
        "cmd": "bat",
        "bicep": "bicep",
        "mligo": "cameligo",
        "clj": "clojure",
        "cljs": "clojure",
        "cljc": "clojure",
        "csprog": "xml",
        "config": "xml",
        "edn": "clojure",
        "coffee": "coffeescript",
        "c": "c",
        "h": "c",
        "cpp": "cpp",
        "cc": "cpp",
        "cxx": "cpp",
        "hpp": "cpp",
        "hh": "cpp",
        "hxx": "cpp",
        "cs": "csharp",
        "csx": "csharp",
        "cake": "csharp",
        "css": "css",
        "cypher": "cypher",
        "cyp": "cypher",
        "dart": "dart",
        "dockerfile": "dockerfile",
        "dtd": "xml",
        "ecl": "ecl",
        "ex": "elixir",
        "exs": "elixir",
        "flow": "flow9",
        "ftl": "freemarker2",
        "ftlh": "freemarker2",
        "ftlx": "freemarker2",
        "fs": "fsharp",
        "fsi": "fsharp",
        "ml": "fsharp",
        "mli": "fsharp",
        "fsx": "fsharp",
        "fsscript": "fsharp",
        "go": "go",
        "graphql": "graphql",
        "gql": "graphql",
        "handlebars": "handlebars",
        "hbs": "handlebars",
        "tf": "hcl",
        "tfvars": "hcl",
        "hcl": "hcl",
        "html": "html",
        "htm": "html",
        "shtml": "html",
        "xhtml": "html",
        "mdoc": "html",
        "jsp": "html",
        "json": "python",
        "asp": "html",
        "aspx": "html",
        "jshtm": "html",
        "ini": "ini",
        "properties": "ini",
        "gitconfig": "ini",
        "java": "java",
        "jav": "java",
        "js": "javascript",
        "es6": "javascript",
        "jsx": "javascript",
        "mjs": "javascript",
        "cjs": "javascript",
        "jl": "julia",
        "kt": "kotlin",
        "kts": "kotlin",
        "less": "less",
        "lex": "lexon",
        "liquid": "liquid",
        "html.liquid": "liquid",
        "lua": "lua",
        "m3": "m3",
        "i3": "m3",
        "mg": "m3",
        "ig": "m3",
        "md": "markdown",
        "markdown": "markdown",
        "mdown": "markdown",
        "mkdn": "markdown",
        "mkd": "markdown",
        "mdwn": "markdown",
        "mdtxt": "markdown",
        "mdtext": "markdown",
        "mdx": "mdx",
        "s": "mips",
        "dax": "msdax",
        "msdax": "msdax",
        "m": "objective-c",
        "pas": "pascal",
        "p": "pascal",
        "pp": "pascal",
        "ligo": "pascaligo",
        "pl": "perl",
        "pm": "perl",
        "php": "php",
        "php4": "php",
        "php5": "php",
        "phtml": "php",
        "props": "xml",
        "ctp": "php",
        "pla": "pla",
        "dats": "postiats",
        "sats": "postiats",
        "hats": "postiats",
        "pq": "powerquery",
        "pqm": "powerquery",
        "ps1": "powershell",
        "psm1": "powershell",
        "psd1": "powershell",
        "proto": "proto",
        "jade": "pug",
        "pug": "pug",
        "py": "python",
        "rpy": "python",
        "pyw": "python",
        "cpy": "python",
        "gyp": "python",
        "gypi": "python",
        "qs": "qsharp",
        "r": "r",
        "rhistory": "r",
        "rmd": "r",
        "rprofile": "r",
        "rt": "r",
        "cshtml": "razor",
        "redis": "redis",
        "rst": "restructuredtext",
        "rb": "ruby",
        "rbx": "ruby",
        "rjs": "ruby",
        "gemspec": "ruby",
        "rs": "rust",
        "rlib": "rust",
        "sb": "sb",
        "scala": "scala",
        "sc": "scala",
        "sbt": "scala",
        "scm": "scheme",
        "ss": "scheme",
        "sch": "scheme",
        "swift": "swift",
        "rkt": "scheme",
        "scss": "scss",
        "sh": "shell",
        "bash": "shell",
        "sol": "sol",
        "aes": "aes",
        "rq": "sparql",
        "sql": "sql",
        "st": "st",
        "iecst": "st",
        "iecplc": "st",
        "lc3lib": "st",
        "targets": "xml",
        "tcpou": "st",
        "tcdut": "st",
        "tcgvl": "st",
        "tcio": "st",
        "sv": "systemverilog",
        "svh": "systemverilog",
        "v": "verilog",
        "vh": "verilog",
        "tcl": "tcl",
        "twig": "twig",
        "ts": "typescript",
        "tsx": "typescript",
        "cts": "typescript",
        "mts": "typescript",
        "vb": "vb",
        "wgsl": "wgsl",
        "wxi": "xml",
        "wxl": "xml",
        "wxs": "xml",
        "xaml": "xml",
        "xml": "xml",
        "xsd": "xml",
        "xsl": "xml",
        "yaml": "yaml",
        "yml": "yaml",
    }
    return ext_to_lang_mappings.get(extension.lower(), "plaintext")


# def map_guesslang_to_monaco_language(file_magic: str) -> str:
#     """
#     Uses guesslang to map unknown text content to a monaco language.

#     NEEDS TENSORFLOW TO RUN!

#     Ref: https://github.com/yoeo/guesslang/blob/master/guesslang/data/languages.json
#     """


def is_valid_chromium_file_path(file_path: str) -> bool:
    """Returns true if the supplied path is a valid Chromium file path."""

    if re.search(
        ".*/(?P<username>.*)/AppData/Local/(Google|Microsoft|BraveSoftware)/(?P<browser>Chrome|Edge|Brave-Browser)/User Data/(?P<type>Local State|.+/History|.+/Login Data|.+/Cookies|.+/Network/Cookies)$",
        file_path,
        re.IGNORECASE,
    ):
        return True
    elif re.search(".*/(?P<username>.*)/AppData/Roaming/Opera Software/Opera Stable/(?P<type>Local State|History|Login Data|Cookies|Network/Cookies)$", file_path, re.IGNORECASE):
        return True
    else:
        return False


def escape_markdown(text: str) -> str:
    """Basic helper to escape markdown specicial characters."""
    parse = re.sub(r"([_*\[\]()~`>\#\+\-=|\.!])", r"\\\1", text)
    reparse = re.sub(r"\\\\([_*\[\]()~`>\#\+\-=|\.!])", r"\1", parse)
    return reparse


def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def remote_css(url):
    st.markdown(f'<link href="{url}" rel="stylesheet">', unsafe_allow_html=True)


def nemesis_post_file(file_bytes):
    """
    Takes a series of raw file bytes and POSTs it to the NEMESIS_API_URL /file API endpoint.
    """
    try:
        r = requests.request("POST", f"{NEMESIS_API_URL}file", data=file_bytes, headers={"Content-Type": "application/octet-stream"})

        if r.status_code != 200:
            st.warning(f"Failed to upload file to Nemesis: {r.status_code}", icon="⚠️")
            return None
        else:
            json_result = r.json()
            if "object_id" in json_result:
                return json_result["object_id"]
            else:
                st.warning(f"Error retrieving 'object_id' field from result", icon="⚠️")
                return None
    except Exception as e:
        st.warning(f"Failed to upload file to Nemesis: {e}", icon="⚠️")
        return None


def nemesis_post_data(data):
    """
    Takes a json blob and POSTs it to the NEMESIS_API_URL /data API endpoint.
    """
    try:
        r = requests.post(f"{NEMESIS_API_URL}data", json=data)
        if r.status_code != 200:
            st.warning(f"Error posting to Nemesis URL {NEMESIS_API_URL}data ({r.status_code}) : {r.json()}", icon="⚠️")
            return None
        else:
            json_result = r.json()
            if "object_id" in json_result:
                return json_result["object_id"]
            else:
                st.warning(f"Error retrieving 'object_id' field from result", icon="⚠️")
                return None
    except Exception as e:
        st.warning(f"Error posting to Nemesis URL {NEMESIS_API_URL}data : {e}", icon="⚠️")
        return None
