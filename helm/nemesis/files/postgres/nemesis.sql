DROP SCHEMA IF EXISTS "nemesis" CASCADE;
CREATE SCHEMA "nemesis";
SET search_path TO "nemesis";

-- used for index processing for file trees
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- used for random UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

START TRANSACTION;

SET TIME ZONE 'UTC';

CREATE TABLE projects (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    project_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration DATE NOT NULL
);

-- this table is only used for inheritence for other tables to enforce these fields
CREATE TABLE project_data (
    project_id TEXT REFERENCES projects (project_id),
    source TEXT,
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration DATE NOT NULL
);

-----------------------------------------------
--
-- Processed Datatypes
--
-----------------------------------------------
CREATE TYPE filesystem_object_type AS ENUM ('file', 'folder');

-- filesystem objects, whether through downloads or listings
CREATE TABLE filesystem_objects (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    id BIGSERIAL PRIMARY KEY,           -- TODO: is this needed now that we have unique_db_id ?
    agent_id TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT,
    extension TEXT,                 -- extracted from the path
    type filesystem_object_type,
    size BIGINT,
    magic_type TEXT,
    creation_time TIMESTAMP WITH TIME ZONE,        -- UTC
    access_time TIMESTAMP WITH TIME ZONE,          -- UTC
    modification_time TIMESTAMP WITH TIME ZONE,    -- UTC
    access_mode INTEGER,            -- *nix permission number
    file_group TEXT,                     -- *nix case sensitive file group membership
    file_id TEXT,                   -- *nix string for an inode or file id
    owner TEXT,                     -- Case sensitive owner (*nix and Windows)
    sddl TEXT,
    nemesis_file_id UUID,           -- Nemesis file UUID `object_id` if the file is uploaded
    UNIQUE (project_id, source, path)
) INHERITS (project_data);

-- Trigram indexing for `filesystem_objects` path search speedup
--  GIN is faster to read but slower to write. GiST is faster to write but slower to read and is smaller on disk.
CREATE INDEX filesystem_objects_on_path_idx ON filesystem_objects USING GIN(path gin_trgm_ops);

-- registry entry objects
CREATE TABLE registry_objects (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value_name TEXT,
    value_kind INTEGER,
    value TEXT,
    sddl TEXT,
    tags TEXT,
    UNIQUE (project_id, source, key, value_name)
) INHERITS (project_data);

-- Trigram indexing for `registry_objects` path search speedup
--  GIN is faster to read but slower to write. GiST is faster to write but slower to read and is smaller on disk.
-- CREATE INDEX registry_objects_on_key_idx ON registry_objects USING GIN(key gin_trgm_ops);
-- currently failing https://stackoverflow.com/questions/42022362/no-unique-or-exclusion-constraint-matching-the-on-conflict

-- Windows services, derived from registry values or submitted manually
CREATE TABLE services (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    binary_path TEXT,
    command_line TEXT,
    description TEXT,
    display_name TEXT,
    name TEXT NOT NULL,
    sddl TEXT,
    service_dll_entrypoint TEXT,
    service_dll_path TEXT,
    service_type SMALLINT,
    start_type SMALLINT,
    state SMALLINT,
    username TEXT,
    filesystem_object_id INT REFERENCES filesystem_objects (id),    -- reference to the service file if it's been downloaded
    UNIQUE (project_id, source, name)
) INHERITS (project_data);

-- Windows named pipes, derived Seatbelt data or submitted manually
CREATE TABLE named_pipes (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    name TEXT not NULL,
    server_process_name TEXT,
    server_process_id INTEGER,
    server_process_path TEXT,
    sddl TEXT
) INHERITS (project_data);

-- An in-between the Elastic and Postgres representations for enriched data
--  This is for ease of use of searching/filtering through the dashboard(s)
CREATE TABLE file_data_enriched (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    object_id UUID,                 -- Nemesis file UUID of the uploaded file
    path TEXT NOT NULL,
    name TEXT,
    size BIGINT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    nemesis_file_type TEXT,
    magic_type TEXT,
    converted_pdf_id UUID,          -- Nemesis file UUID if there's a converted PDF linked to this file
    extracted_plaintext_id UUID,    -- Nemesis file UUID if there's extracted plaintext linked to this file
    extracted_source_id UUID,       -- Nemesis file UUID if there's extracted source code linked to this file
    tags TEXT[],                    -- hash_dpapi, has_deserialization, etc.
    originating_object_id UUID,     -- Nemesis file UUID of the file/archive the file originates from
    UNIQUE (object_id)
) INHERITS (project_data);

-- Network connection, derived Seatbelt data or submitted manually
CREATE TABLE network_connections (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    local_address TEXT,
    remote_address TEXT,
    protocol TEXT,
    state TEXT,
    process_id INTEGER,
    process_name TEXT,
    service TEXT
) INHERITS (project_data);

-----------------------------------------------
--
-- DPAPI
--
-----------------------------------------------

-- The DPAPI domain backupkey
CREATE TABLE dpapi_domain_backupkeys (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    domain_backupkey_guid UUID PRIMARY KEY, -- linked to `domain_backupkey_guid` in dpapi_masterkeys
    domain_controller TEXT NOT NULL,
    domain_backupkey_bytes BYTEA NOT NULL   -- actual bytes (~1k) of the domain backup key
) INHERITS (project_data);

-- individual masterkey files
CREATE TABLE dpapi_masterkeys (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    object_id UUID,                         -- Nemesis file UUID `object_id` of the uploaded file
    type TEXT,                              -- "domain_user", "local_user", or "machine"
    username TEXT,                          -- username of the user who owns the key
    user_sid TEXT,                          -- user SID of the user who owns the key
    masterkey_guid UUID PRIMARY KEY,        -- linked to `masterkey_guid` in dpapi_blobs
    is_decrypted BOOLEAN,                   -- true if key is currently decrypted
    masterkey_bytes BYTEA,                  -- raw bytes of the masterkey
    domain_backupkey_guid UUID,             -- linked to `domain_backupkey_guid` in dpapi_domain_backupkeys
    domainkey_pb_secret BYTEA,              -- bytes encrypted by the domain backup key
    decrypted_key_full BYTEA,               -- the full decrypted master key
    decrypted_key_sha1 BYTEA                -- the sha1 representation of the masterkey
) INHERITS (project_data);

-- individual DPAPI data blobs
CREATE TABLE dpapi_blobs (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    dpapi_blob_id UUID PRIMARY KEY,         -- unique identifier so originating documents can keep track of which DPAPI blobs were extracted from it (NOT S3)
    originating_object_id UUID,             -- Nemesis file UUID of the file the DPAPI blob was carved from
    originating_registry_id UUID,           -- unique_db_id of the registry_objects key that the blob was carved from
    masterkey_guid UUID NOT NULL,           -- linked to `masterkey_guid` in dpapi_masterkeys
    is_file BOOLEAN,
    is_decrypted BOOLEAN,
    enc_data_bytes BYTEA,                   -- If the encrypted data is < 1024 bytes it will be stored as bytes in this field
    enc_data_object_id UUID,                -- If the encrypted data is > 1024 bytes it will be will be stored in S3 as a UUID file
    dec_data_bytes BYTEA,                   -- If the decrypted data is < 1024 bytes it will be stored as bytes in this field
    dec_data_object_id UUID                 -- If the decrypted data is > 1024 bytes it will be will be stored in S3 as a UUID file
) INHERITS (project_data);


-----------------------------------------------
--
-- Chromium
--
-----------------------------------------------

-- Entries from the "urls" table in a Chromium "History" database
CREATE TABLE chromium_history (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                 -- Nemesis file UUID if this entry originated from a file
    user_data_directory TEXT,                   -- specific user Chromium data directory path, if applicable
    username TEXT,                              -- username extracted from user_data_directory, if applicable
    browser TEXT,                               -- browser name extracted from user_data_directory, if applicable
    url TEXT,                                   -- extracted from the Chromium DB
    title TEXT,                                 -- extracted from the Chromium DB
    visit_count INTEGER,                        -- extracted from the Chromium DB
    typed_count INTEGER,                        -- extracted from the Chromium DB
    last_visit_time TIMESTAMP WITH TIME ZONE,   -- extracted from the Chromium DB
    UNIQUE (source, agent_id, originating_object_id, user_data_directory, url)
) INHERITS (project_data);

-- Entries from the "downloads" table in a Chromium "History" database
CREATE TABLE chromium_downloads (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                 -- Nemesis file UUID if this entry originated from a file
    user_data_directory TEXT,                   -- specific user Chromium data directory path, if applicable
    username TEXT,                              -- username extracted from user_data_directory, if applicable
    browser TEXT,                               -- browser name extracted from user_data_directory, if applicable
    url TEXT,                                   -- extracted from the Chromium DB `tab_url` field
    download_path TEXT,                         -- extracted from the Chromium DB `target_path` field
    start_time TIMESTAMP WITH TIME ZONE,        -- extracted from the Chromium DB
    end_time TIMESTAMP WITH TIME ZONE,          -- extracted from the Chromium DB
    total_bytes INTEGER,                        -- extracted from the Chromium DB
    danger_type TEXT,                           -- extracted from the Chromium DB, converted from int
    UNIQUE (source, agent_id, originating_object_id, user_data_directory, download_path)
) INHERITS (project_data);

-- Entries from the saved "logins" table in a Chromium "Login Data" database
CREATE TABLE chromium_logins (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                         -- Nemesis file UUID if this entry originated from a file
    user_data_directory TEXT,                           -- specific user Chromium data directory path, if applicable
    username TEXT,                                      -- username extracted from user_data_directory, if applicable
    browser TEXT,                                       -- browser name extracted from user_data_directory, if applicable
    origin_url TEXT,                                    -- extracted from the Chromium DB
    username_value TEXT,                                -- extracted from the Chromium DB
    password_value_enc BYTEA,                           -- extracted from the Chromium DB `password_value` field
    signon_realm TEXT,                                  -- extracted from the Chromium DB
    date_created TIMESTAMP WITH TIME ZONE,              -- extracted from the Chromium DB
    date_last_used TIMESTAMP WITH TIME ZONE,            -- extracted from the Chromium DB
    date_password_modified TIMESTAMP WITH TIME ZONE,    -- extracted from the Chromium DB
    times_used INTEGER,                                 -- extracted from the Chromium DB
    encryption_type TEXT,                               -- carved from the `password_value_enc` bytes
    masterkey_guid UUID,                                -- if encryption_type==dpapi, linked to `masterkey_guid` in dpapi_masterkeys
    is_decrypted BOOLEAN,
    password_value_dec TEXT,
    UNIQUE (source, agent_id, originating_object_id, user_data_directory, origin_url, username_value, password_value_enc)
) INHERITS (project_data);

-- Entries from the "cookies" table in a Chromium "Cookies" database
-- https://chromium.googlesource.com/chromium/src/net/+/refs/heads/main/extras/sqlite/sqlite_persistent_cookie_store.cc#123
CREATE TABLE chromium_cookies (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                         -- Nemesis file UUID if this entry originated from a file
    user_data_directory TEXT,                           -- specific user Chromium data directory path, if applicable
    username TEXT,                                      -- username extracted from user_data_directory, if applicable
    browser TEXT,                                       -- browser name extracted from user_data_directory, if applicable
    host_key TEXT,                                      -- extracted from the Chromium DB
    name TEXT,                                          -- extracted from the Chromium DB
    path TEXT,                                          -- extracted from the Chromium DB
    creation_utc TIMESTAMP WITH TIME ZONE,              -- extracted from the Chromium DB
    expires_utc TIMESTAMP WITH TIME ZONE,               -- extracted from the Chromium DB
    last_access_utc TIMESTAMP WITH TIME ZONE,           -- extracted from the Chromium DB
    last_update_utc TIMESTAMP WITH TIME ZONE,           -- extracted from the Chromium DB
    is_secure BOOLEAN,                                  -- extracted from the Chromium DB
    is_httponly BOOLEAN,                                -- extracted from the Chromium DB
    is_session BOOLEAN,                                 -- extracted from the Chromium DB
    samesite TEXT,                                      -- extracted from the Chromium DB, translated from int
    source_port INTEGER,                                -- extracted from the Chromium DB
    value_enc BYTEA,                                    -- extracted from the Chromium DB `encrypted_value` field
    encryption_type TEXT,                               -- carved from the `value_enc` bytes
    masterkey_guid UUID,                                -- if encryption_type==dpapi, linked to `masterkey_guid` in dpapi_masterkeys
    is_decrypted BOOLEAN,
    value_dec TEXT,
    UNIQUE (source, agent_id, originating_object_id, user_data_directory, host_key, name, path)
) INHERITS (project_data);

-- Information/encrypted key from a Chromium "Local State" file
--   The data["os_crypt"]["encrypted_key"] entry is used to encrypt new Chromium logins/cookies
CREATE TABLE chromium_state_files (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                 -- Nemesis file UUID if this entry originated from a file
    user_data_directory TEXT,                   -- specific user Chromium data directory path, if applicable
    username TEXT,                              -- username extracted from user_data_directory, if applicable
    browser TEXT,                               -- browser name extracted from user_data_directory, if applicable
    installation_date DATE,                     -- extracted from the Chromium `Local State` file
    launch_count INTEGER,                       -- extracted from the Chromium `Local State` file
    masterkey_guid UUID,                        -- linked to `masterkey_guid` in dpapi_masterkeys
    key_bytes_enc BYTEA NOT NULL,               -- extracted from the Chromium `Local State` file
    app_bound_fixed_data_enc BYTEA NOT NULL,    -- extracted from the Chromium `Local State` file
    is_decrypted BOOLEAN,
    key_bytes_dec BYTEA NOT NULL,
    app_bound_fixed_data_dec BYTEA NOT NULL,
    UNIQUE (source, agent_id, originating_object_id, user_data_directory)
) INHERITS (project_data);


-----------------------------------------------
--
-- Slack
--
-----------------------------------------------

-- Parsed downloads from a "slack-downloads" file or Seatbelt json
CREATE TABLE slack_downloads (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                 -- Nemesis file UUID if this entry originated from a file
    username TEXT,                              -- username extracted from file path, if applicable
    workspace_id TEXT,                          -- extracted from slack-downloads
    download_id TEXT,                           -- extracted from slack-downloads
    team_id TEXT,                               -- extracted from slack-downloads
    user_id TEXT,                               -- extracted from slack-downloads
    url TEXT,                                   -- extracted from slack-downloads
    download_path TEXT,                         -- extracted from slack-downloads
    download_state TEXT,                        -- extracted from slack-downloads
    start_time TIMESTAMP WITH TIME ZONE,        -- extracted from slack-downloads
    end_time TIMESTAMP WITH TIME ZONE,          -- extracted from slack-downloads
    UNIQUE (source, agent_id, originating_object_id, workspace_id, download_id)
) INHERITS (project_data);

-- Parsed downloads from a "slack-workspaces" file or Seatbelt json
CREATE TABLE slack_workspaces (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                 -- Nemesis file UUID if this entry originated from a file
    username TEXT,                              -- username extracted from file path, if applicable
    workspace_id TEXT,                          -- extracted from slack-workspaces
    workspace_domain TEXT,                      -- extracted from slack-workspaces
    workspace_name TEXT,                        -- extracted from slack-workspaces
    workspace_icon_url TEXT,                    -- extracted from slack-workspaces
    UNIQUE (source, agent_id, originating_object_id, workspace_id, workspace_domain, workspace_name)
) INHERITS (project_data);


-----------------------------------------------
--
-- Hashes and authentication data
--
-----------------------------------------------

-- Hashes extracted from plaintext files
CREATE TABLE extracted_hashes (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    originating_object_id UUID,                             -- Nemesis file UUID of the file the hash was carved from, if applicable
    hash_type TEXT,                                         -- Cloned from `type` in authentication_data
    hash_value TEXT NOT NULL,                               -- Value of extracted hash
    hashcat_formatted_value TEXT,                           -- Optional Hashcat-formatted hash value
    jtr_formatted_value TEXT,                               -- Optional JTR-formatted hash value
    is_cracked BOOLEAN,                                     -- True if the hash has been cracked
    checked_against_top_passwords BOOLEAN,                  -- True if the top X passwords have been checked against this
    is_submitted_to_cracker BOOLEAN,                        -- True if the hash has submitted to a longer-run cracking job
    cracker_submission_time TIMESTAMP WITH TIME ZONE,       -- Time the hash was submitted to a longer-run cracking job
    cracker_cracked_time TIMESTAMP WITH TIME ZONE,          -- Time the hash was cracked by a longer-run cracking job
    plaintext_value TEXT,                                   -- The data value if the hash has been cracked
    hash_value_md5_hash UUID GENERATED ALWAYS AS (MD5(hash_value)::uuid) STORED,    -- used in case the hash value is vvv longboi
    UNIQUE (timestamp, originating_object_id, hash_value_md5_hash)
) INHERITS (project_data);


-- Authentication data submitted to the API or surfaced internally
CREATE TABLE authentication_data (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT NOT NULL,
    data TEXT,
    type TEXT,
    is_file BOOLEAN,
    uri TEXT,
    username TEXT,
    notes TEXT,
    originating_object_id UUID                             -- Nemesis file UUID if the auth data was carved from a file
) INHERITS (project_data);


-----------------------------------------------
--
-- Host/agent info
--
-----------------------------------------------

-- Basic information surfaced about encountered hosts
CREATE TABLE hosts (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    id SERIAL PRIMARY KEY,
    hostname TEXT,
    description TEXT,
    os_type TEXT,
    windows_major_version NUMERIC(9,1),
    windows_build TEXT,
    windows_release TEXT,
    windows_domain TEXT,
    linux_kernel_version TEXT,
    linux_distributor TEXT,
    linux_release TEXT,
    agent_ids TEXT[],
    UNIQUE (hostname)
) INHERITS (project_data);

-- Basic information surfaced about agents that have submitted data
CREATE TABLE agents (
    unique_db_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id TEXT PRIMARY KEY,                      -- ID from Cobalt Strike/Mythic/etc.
    host_id INT REFERENCES hosts (id),              -- reference to host the agent is running on
    agent_type TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_alive BOOLEAN,
    arch TEXT,
    process_name TEXT,
    process_id INTEGER,
    process_username TEXT,
    UNIQUE (agent_id)
) INHERITS (project_data);


-----------------------------------------------
--
-- Triage/Analysis
--
-----------------------------------------------

-- Tracks objects in the DB that have been triaged by operator input
CREATE TABLE triage (
    unique_db_id UUID NOT NULL PRIMARY KEY,     -- unique_db_id UUID of the object that's been triaged
    table_name TEXT,                            -- optional table name the unique_db_id originates from
    modification_time TIMESTAMP WITH TIME ZONE, -- Last time the field was modified
    expiration DATE NOT NULL,                   -- date when the entry should be wiped from the database
    operator TEXT,                              -- optional name of the operator making the change
    value TEXT                                  -- Useful/Not Useful/Unknown, or not set
);

-- Tracks objects in the DB that have been triaged by operator input
CREATE TABLE notes (
    unique_db_id UUID NOT NULL PRIMARY KEY,     -- unique_db_id UUID of the object that has a note added
    table_name TEXT,                            -- optional table name the unique_db_id originates from
    modification_time TIMESTAMP WITH TIME ZONE, -- Last time the field was modified
    expiration DATE NOT NULL,                   -- date when the entry should be wiped from the database
    operator TEXT,                              -- optional name of the operator making the change
    value TEXT                                  -- text of the note an operator left
);


-----------------------------------------------
--
-- Reprocessing
--
-----------------------------------------------

-- All incoming data POST messages are stored in their raw form so
--  we can replay them later for reprocessing.
CREATE TABLE api_data_messages (
    message_id TEXT PRIMARY KEY,    -- the unique message ID of the posted data message
    message_bytes BYTEA NOT NULL,   -- raw bytes of an incoming message
    expiration DATE NOT NULL        -- date when the message should be wiped from the database
);

COMMIT;
