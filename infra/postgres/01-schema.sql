CREATE EXTENSION IF NOT EXISTS pg_trgm;

-----------------------
-- FILES
-----------------------
CREATE TABLE IF NOT EXISTS files (
    object_id UUID PRIMARY KEY,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration TIMESTAMP WITH TIME ZONE,
    path TEXT,
    originating_object_id UUID,
    originating_container_id UUID, -- for large container processing
    nesting_level INTEGER,
    file_creation_time TIMESTAMP WITH TIME ZONE,
    file_access_time TIMESTAMP WITH TIME ZONE,
    file_modification_time TIMESTAMP WITH TIME ZONE,
    security_info JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-----------------------
-- ENRICHED FILES
-----------------------
CREATE TABLE IF NOT EXISTS files_enriched (
    object_id UUID PRIMARY KEY,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration TIMESTAMP WITH TIME ZONE,
    path TEXT,
    file_name VARCHAR(255),
    extension VARCHAR(50),
    size BIGINT,
    magic_type TEXT,
    mime_type TEXT,
    is_plaintext BOOLEAN,
    is_container BOOLEAN,
    originating_object_id UUID,
    originating_container_id UUID, -- for large container processing
    nesting_level INTEGER,
    file_creation_time TIMESTAMP WITH TIME ZONE,
    file_access_time TIMESTAMP WITH TIME ZONE,
    file_modification_time TIMESTAMP WITH TIME ZONE,
    security_info JSONB,
    hashes JSONB,
    file_tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrichments (
    enrichment_id BIGSERIAL PRIMARY KEY,
    object_id UUID NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    result_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transforms (
    transform_id BIGSERIAL PRIMARY KEY,
    object_id UUID NOT NULL,
    type VARCHAR(255) NOT NULL,
    transform_object_id UUID NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_tags (
    tag_name VARCHAR(255) PRIMARY KEY
);

-- findings are a bit further down

CREATE TABLE IF NOT EXISTS files_view_history (
    id BIGSERIAL PRIMARY KEY,
    object_id UUID NOT NULL,
    username VARCHAR(255) NOT NULL,
    automated BOOLEAN,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files_feedback (
    object_id UUID PRIMARY KEY,
    username VARCHAR(255), -- last person who left the feedback
    automated BOOLEAN,
    missing_parser BOOLEAN,
    missing_file_viewer BOOLEAN,
    sensitive_info_not_detected BOOLEAN,
    comments TEXT,
    alert_sent BOOLEAN DEFAULT false,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE
);


-----------------------
-- Extracted File Features
-----------------------
CREATE TABLE IF NOT EXISTS files_enriched_dataset (
    object_id UUID PRIMARY KEY,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration TIMESTAMP WITH TIME ZONE,
    path TEXT,
    file_creation_time TIMESTAMP WITH TIME ZONE,
    file_access_time TIMESTAMP WITH TIME ZONE,
    file_modification_time TIMESTAMP WITH TIME ZONE,
    features_version VARCHAR(255),
    individual_features JSONB,          -- individual features
    sibling_features JSONB,             -- features based on files in the same folder (and same agent)
    agent_population_features JSONB,    -- population features segmented per agent_id
    global_population_features JSONB,   -- global population features
    labels JSONB,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create a GiST index for path matching
CREATE INDEX idx_files_enriched_dataset_path_trgm ON files_enriched_dataset USING gist (path gist_trgm_ops);

-- Create indexes for finding siblings (composite index with agent_id and path)
CREATE INDEX idx_files_enriched_dataset_siblings ON files_enriched_dataset(agent_id, path);

-- helper for pulling out 'sibling' files
CREATE OR REPLACE FUNCTION get_parent_path(path text)
RETURNS text AS $$
BEGIN
    -- Handle both Windows and Unix paths
    RETURN regexp_replace(
        path,
        '[\\/][^\\/]*$',
        ''
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- Then you can find siblings with queries like:
-- SELECT * FROM files_enriched_dataset
-- WHERE agent_id = $1
-- AND get_parent_path(path) = get_parent_path($2);


-----------------------
-- FINDINGS
-----------------------
CREATE TABLE IF NOT EXISTS findings (
    finding_id BIGSERIAL PRIMARY KEY,
    finding_name VARCHAR(255) NOT NULL,
    category VARCHAR(255) NOT NULL,
    severity INTEGER NOT NULL,
    object_id UUID NOT NULL,
    origin_type VARCHAR(255) NOT NULL,
    origin_name VARCHAR(255) NOT NULL,
    raw_data JSONB NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    triage_id BIGINT
);

CREATE TABLE IF NOT EXISTS findings_triage_history (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL,
    username VARCHAR(255) NOT NULL,
    automated BOOLEAN,
    value VARCHAR(255) NOT NULL,
    explanation VARCHAR(5000),
    confidence REAL,
    true_positive_context VARCHAR(5000),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- Add foreign key constraints if they don't exist
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_files_view_history_object_id') THEN
        ALTER TABLE files_view_history
        ADD CONSTRAINT fk_files_view_history_object_id
        FOREIGN KEY (object_id)
        REFERENCES files_enriched(object_id)
        ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_findings_triage_id') THEN
        ALTER TABLE findings
        ADD CONSTRAINT fk_findings_triage_id
        FOREIGN KEY (triage_id)
        REFERENCES findings_triage_history(id);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_findings_object_id') THEN
        ALTER TABLE findings
        ADD CONSTRAINT fk_findings_object_id
        FOREIGN KEY (object_id)
        REFERENCES files_enriched(object_id)
        ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_findings_triage_history_finding_id') THEN
        ALTER TABLE findings_triage_history
        ADD CONSTRAINT fk_findings_triage_history_finding_id
        FOREIGN KEY (finding_id)
        REFERENCES findings(finding_id)
        ON DELETE CASCADE;
    END IF;
END $$;


-- Create indexes if they don't exist
CREATE INDEX IF NOT EXISTS idx_files_enriched_agent_id ON files_enriched(agent_id);
CREATE INDEX IF NOT EXISTS idx_files_enriched_hashes ON files_enriched USING GIN (hashes);
CREATE INDEX IF NOT EXISTS idx_files_enriched_path_trgm ON files_enriched USING gist (path gist_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_findings_data_gin ON findings USING GIN (data);
CREATE INDEX IF NOT EXISTS idx_files_view_history_username ON files_view_history(username);
CREATE INDEX IF NOT EXISTS idx_files_view_history_composite ON files_view_history(object_id, username, timestamp);
CREATE INDEX IF NOT EXISTS idx_files_enriched_dataset_agent_id ON files_enriched_dataset(agent_id);



-----------------------
-- PLAINTEXT CONTENT
-----------------------
CREATE TABLE IF NOT EXISTS plaintext_content (
    object_id UUID REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    chunk_number INTEGER,
    content TEXT,
    -- Use simple configuration to preserve all terms without stemming
    content_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (object_id, chunk_number)
);

-- Create GIN index for full-text search
CREATE INDEX IF NOT EXISTS idx_plaintext_content_vector ON plaintext_content USING GIN (content_vector);
--- CREATE INDEX IF NOT EXISTS idx_plaintext_content_vector ON plaintext_content USING GIN (content_vector gin_trgm_ops); --- trigram-based searches, which can be useful for partial-word matching?

-----------------------
-- SEARCH VIEW
-----------------------
-- Drop any existing function/view/type
DROP FUNCTION IF EXISTS public.search_documents CASCADE;
DROP TYPE IF EXISTS public.search_result CASCADE;
DROP VIEW IF EXISTS public.document_search_results CASCADE;

-- Create the view
CREATE OR REPLACE VIEW public.document_search_results AS
SELECT
    pc.object_id,
    pc.chunk_number,
    pc.content,
    pc.content_vector,
    ef.file_name,
    ef.path,
    ef.extension,
    ef.project,
    ef.agent_id,
    ef.source,
    ef."timestamp"::timestamp with time zone
FROM plaintext_content pc
JOIN files_enriched ef ON pc.object_id = ef.object_id;

-- Create a simple search function that uses the view
CREATE OR REPLACE FUNCTION public.search_documents(
    search_query text,
    path_pattern text DEFAULT NULL,
    agent_pattern text DEFAULT NULL,
    project_name text DEFAULT NULL,
    start_date timestamp with time zone DEFAULT NULL,
    end_date timestamp with time zone DEFAULT NULL,
    max_results integer DEFAULT 100,
    source_pattern text DEFAULT NULL
) RETURNS SETOF document_search_results
STABLE
LANGUAGE sql
AS $$
    WITH ranked_chunks AS (
        SELECT *,
            ROW_NUMBER() OVER (
                PARTITION BY object_id
                ORDER BY chunk_number ASC
            ) as rn
        FROM document_search_results
        WHERE
            content_vector @@ plainto_tsquery('simple', search_query)
            AND (path_pattern IS NULL OR path LIKE path_pattern)
            AND (agent_pattern IS NULL OR agent_id LIKE agent_pattern)
            AND (project_name IS NULL OR project = project_name)
            AND (start_date IS NULL OR "timestamp" >= start_date)
            AND (end_date IS NULL OR "timestamp" <= end_date)
            AND (source_pattern IS NULL OR source IS NULL OR source LIKE source_pattern)
    )
    SELECT
        object_id,
        chunk_number,
        content,
        content_vector,
        file_name,
        path,
        extension,
        project,
        agent_id,
        source,
        "timestamp"
    FROM ranked_chunks
    WHERE rn = 1
    ORDER BY "timestamp" DESC
    LIMIT max_results;
$$;

-- compression
ALTER TABLE plaintext_content
ALTER COLUMN content SET STORAGE EXTENDED;

-- Add work_mem adjustment for text search operations
SET work_mem = '256MB';



-----------------------
-- Yara
-----------------------
CREATE TABLE IF NOT EXISTS yara_rules (
    name VARCHAR(255) NOT NULL PRIMARY KEY,
    content TEXT NOT NULL,
    source VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    alert_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-----------------------
-- Agent Prompts
-----------------------
CREATE TABLE IF NOT EXISTS agent_prompts (
    name VARCHAR(255) NOT NULL PRIMARY KEY,
    description TEXT,
    prompt TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-----------------------
-- Alert Settings
-----------------------
CREATE TABLE IF NOT EXISTS alert_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    alerting_enabled BOOLEAN NOT NULL DEFAULT true,
    minimum_severity INTEGER NOT NULL DEFAULT 4 CHECK (minimum_severity >= 0 AND minimum_severity <= 10),
    category_excluded TEXT[] DEFAULT '{}',
    category_included TEXT[] DEFAULT '{}',
    file_path_excluded_regex TEXT[] DEFAULT '{}',
    file_path_included_regex TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT single_row_check CHECK (id = 1)
);


-----------------------
-- FILE LINKINGS
-----------------------
CREATE TABLE IF NOT EXISTS file_linkings (
    linking_id BIGSERIAL PRIMARY KEY,
    source VARCHAR(1000) NOT NULL,
    file_path_1 TEXT NOT NULL,
    file_path_2 TEXT NOT NULL,
    link_type VARCHAR(255),  -- Optional: to specify the type of relationship
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source, file_path_1, file_path_2)
);

-- Create indexes for efficient lookups in both directions
CREATE INDEX IF NOT EXISTS idx_file_linkings_file_1 ON file_linkings(file_path_1);
CREATE INDEX IF NOT EXISTS idx_file_linkings_file_2 ON file_linkings(file_path_2);
CREATE INDEX IF NOT EXISTS idx_file_linkings_source ON file_linkings(source);


-----------------------
-- FILE LISTINGS
-----------------------
CREATE TABLE IF NOT EXISTS file_listings (
    listing_id BIGSERIAL PRIMARY KEY,
    source VARCHAR(1000) NOT NULL,
    path TEXT NOT NULL,
    object_id UUID,
    status VARCHAR(50) NOT NULL CHECK (status IN ('needs_to_be_collected', 'not_exists', 'collected', 'not_wanted')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    path_lower TEXT GENERATED ALWAYS AS (LOWER(path)) STORED,
    UNIQUE(source, path_lower),
    FOREIGN KEY (object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE
);

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_file_listings_source ON file_listings(source);
CREATE INDEX IF NOT EXISTS idx_file_listings_status ON file_listings(status);
CREATE INDEX IF NOT EXISTS idx_file_listings_object_id ON file_listings(object_id);
-- Create composite index for efficient path prefix queries
CREATE INDEX IF NOT EXISTS idx_file_listings_source_path ON file_listings(source, path);
-- Create trigram index for path pattern matching
CREATE INDEX IF NOT EXISTS idx_file_listings_path_trgm ON file_listings USING gist (path gist_trgm_ops);

-- Helper functions for file browser hierarchical navigation
CREATE OR REPLACE FUNCTION get_path_depth(file_path text)
RETURNS integer AS $$
BEGIN
    -- Count forward slashes to determine depth
    -- Root files (no slash) are depth 0, /folder/file is depth 1, etc.
    IF file_path = '' OR file_path IS NULL THEN
        RETURN 0;
    END IF;
    RETURN array_length(string_to_array(file_path, '/'), 1) - 1;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION get_path_parent(file_path text)
RETURNS text AS $$
BEGIN
    -- Return parent path, handling edge cases
    IF file_path IS NULL OR file_path = '' OR position('/' in file_path) = 0 THEN
        RETURN '';
    END IF;
    RETURN regexp_replace(file_path, '/[^/]*$', '');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION get_path_filename(file_path text)
RETURNS text AS $$
BEGIN
    -- Extract just the filename/folder name from full path
    IF file_path IS NULL OR file_path = '' THEN
        RETURN '';
    END IF;
    RETURN regexp_replace(file_path, '^.*/', '');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION is_file_path(file_path text)
RETURNS boolean AS $$
BEGIN
    -- Simple heuristic: if path has an extension, it's likely a file
    -- This isn't perfect but works for most cases
    IF file_path IS NULL OR file_path = '' THEN
        RETURN false;
    END IF;
    -- Check if the last part after the final slash contains a dot
    RETURN get_path_filename(file_path) LIKE '%.%';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- View for hierarchical file browser queries
-- This creates virtual folder entries for efficient navigation
CREATE OR REPLACE VIEW file_listings_hierarchy AS
WITH RECURSIVE folder_paths AS (
    -- Get all unique folder paths from file paths
    SELECT DISTINCT
        source,
        get_path_parent(path) as folder_path,
        get_path_depth(get_path_parent(path)) as depth
    FROM file_listings
    WHERE get_path_parent(path) != ''

    UNION

    -- Add parent folders recursively
    SELECT
        source,
        get_path_parent(folder_path) as folder_path,
        get_path_depth(get_path_parent(folder_path)) as depth
    FROM folder_paths
    WHERE get_path_parent(folder_path) != '' AND get_path_parent(folder_path) != folder_path
)
SELECT
    source,
    folder_path as path,
    'folder' as item_type,
    null::uuid as object_id,
    'folder' as status,
    depth,
    get_path_parent(folder_path) as parent_path,
    get_path_filename(folder_path) as name
FROM folder_paths
WHERE folder_path != ''

UNION ALL

SELECT
    source,
    path,
    'file' as item_type,
    object_id,
    status,
    get_path_depth(path) as depth,
    get_path_parent(path) as parent_path,
    get_path_filename(path) as name
FROM file_listings;


-----------------------
-- CREATE UPDATE FIELD TRIGGER
-----------------------

-- Updates the "updated_at" value for tables we update
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
        NEW.updated_at = CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for each table
CREATE OR REPLACE TRIGGER update_files_updated_at
    BEFORE UPDATE ON files
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_files_enriched_updated_at
    BEFORE UPDATE ON files_enriched
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_yara_rules_updated_at
    BEFORE UPDATE ON yara_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_agent_prompts_updated_at
    BEFORE UPDATE ON agent_prompts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_alert_settings_updated_at
    BEFORE UPDATE ON alert_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_enrichments_updated_at
    BEFORE UPDATE ON enrichments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_enrichments_updated_at
    BEFORE UPDATE ON transforms
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_files_enriched_dataset_updated_at
    BEFORE UPDATE ON files_enriched_dataset
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_file_linkings_updated_at
    BEFORE UPDATE ON file_linkings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_file_listings_updated_at
    BEFORE UPDATE ON file_listings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-----------------------
-- Workflow tracking
-----------------------
CREATE TABLE IF NOT EXISTS workflows (
    wf_id VARCHAR(255) NOT NULL PRIMARY KEY,
    object_id UUID,
    filename VARCHAR(255),
    enrichments_success TEXT[] DEFAULT '{}',
    enrichments_failure TEXT[] DEFAULT '{}',
    status TEXT NOT NULL,
    runtime_seconds REAL,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-----------------------
-- Container Processing Tracking
-----------------------
CREATE TABLE IF NOT EXISTS container_processing (
    container_id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    container_type VARCHAR(50) NOT NULL,
    original_filename VARCHAR(255),
    original_size BIGINT,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'submitted',
    total_files_extracted INTEGER DEFAULT 0,
    total_bytes_extracted BIGINT DEFAULT 0,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiration TIMESTAMP WITH TIME ZONE,
    processing_started_at TIMESTAMP WITH TIME ZONE,
    processing_completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    workflows_completed INTEGER DEFAULT 0,
    workflows_failed INTEGER DEFAULT 0,
    workflows_total INTEGER DEFAULT 0,
    total_bytes_processed BIGINT DEFAULT 0
);


-- Create phoenix database
CREATE DATABASE phoenix;


-----------------------
-- Chromium schema/tables
-----------------------

CREATE SCHEMA chromium;

-- "urls" table in "History" file
CREATE TABLE IF NOT EXISTS chromium.history (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    username TEXT,                              -- username extracted from user data directory, if applicable
    browser TEXT,                               -- browser name extracted from user data directory, if applicable

    url TEXT,                                   -- extracted from the Chromium DB
    title TEXT,                                 -- extracted from the Chromium DB
    visit_count INTEGER,                        -- extracted from the Chromium DB
    last_visit_time TIMESTAMP WITH TIME ZONE,   -- extracted from the Chromium DB

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    UNIQUE (source, username, browser, url, title, last_visit_time)
);

-- "downloads" table in "History" file
CREATE TABLE IF NOT EXISTS chromium.downloads (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    username TEXT,                              -- username extracted from user data directory, if applicable
    browser TEXT,                               -- browser name extracted from user data directory, if applicable

    url TEXT,                                   -- extracted from the Chromium DB
    download_path TEXT,                         -- extracted from the Chromium DB `target_path` field
    start_time TIMESTAMP WITH TIME ZONE,        -- extracted from the Chromium DB
    end_time TIMESTAMP WITH TIME ZONE,          -- extracted from the Chromium DB
    total_bytes INTEGER,                        -- extracted from the Chromium DB

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    UNIQUE (source, username, browser, url, download_path, start_time)
);

-- extracted from a Chromium "Local State" file
CREATE TABLE chromium.state_keys (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    username TEXT,                                      -- username extracted from user data directory, if applicable
    browser TEXT,                                       -- browser name extracted from user data directory, if applicable

    key_masterkey_guid UUID,                            -- associated masterkey GUID for key_bytes_enc
    key_bytes_enc BYTEA,                                -- os_crypt.encrypted_key in Chromium `Local State` file (pre v127)
    key_bytes_dec BYTEA,
    key_is_decrypted BOOLEAN,

    app_bound_key_enc BYTEA,                            -- os_crypt.app_bound_encrypted_key in Chromium `Local State` file (post v127)
    app_bound_key_system_masterkey_guid UUID,           -- associated _system_ masterkey GUID for key_bytes_enc
    app_bound_key_system_dec BYTEA,                     -- intermediate dec value after the SYSTEM key has been used
    app_bound_key_user_masterkey_guid UUID,             -- associated _user_ masterkey GUID for app_bound_key_system_dec
    app_bound_key_user_dec BYTEA,                       -- intermediate dec value after the USER key has been used (before chromekey for v3)
    app_bound_key_dec BYTEA,                            -- completely dec value
    app_bound_key_is_decrypted BOOLEAN,

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    UNIQUE (source, username, browser)
);

-- AES keys extracted from a CNG "Google Chromekey1" CNG file from C:\ProgramData\Microsoft\Crypto\SystemKeys\
--      Used in v3 of the Chromium ABE decryption
CREATE TABLE chromium.chrome_keys (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),                               -- should only be one key per host/source
    project VARCHAR(255),

    key_masterkey_guid UUID,                            -- associated _system_ masterkey GUID for key_bytes_enc
    key_bytes_enc BYTEA,                                -- the raw DPAPI blob bytes from the CNG file
    key_bytes_dec BYTEA,                                -- completely dec AES key value
    key_is_decrypted BOOLEAN,

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    UNIQUE (key_masterkey_guid)
);

-- Create indexes for masterkey GUID lookups on state_keys
CREATE INDEX IF NOT EXISTS idx_state_keys_key_masterkey_guid ON chromium.state_keys(key_masterkey_guid) WHERE key_is_decrypted = FALSE;
CREATE INDEX IF NOT EXISTS idx_state_keys_app_bound_system_mk_guid ON chromium.state_keys(app_bound_key_system_masterkey_guid) WHERE length(app_bound_key_system_dec) = 0;
CREATE INDEX IF NOT EXISTS idx_state_keys_app_bound_user_mk_guid ON chromium.state_keys(app_bound_key_user_masterkey_guid) WHERE length(app_bound_key_user_dec) = 0;

-- "logins" table in "Login Data" file
CREATE TABLE IF NOT EXISTS chromium.logins (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    username TEXT,                                      -- username extracted from user data directory, if applicable
    browser TEXT,                                       -- browser name extracted from user data directory, if applicable

    origin_url TEXT,                                    -- extracted from the Chromium DB
    username_value TEXT,                                -- extracted from the Chromium DB
    signon_realm TEXT,                                  -- extracted from the Chromium DB
    date_created TIMESTAMP WITH TIME ZONE,              -- extracted from the Chromium DB
    date_last_used TIMESTAMP WITH TIME ZONE,            -- extracted from the Chromium DB
    date_password_modified TIMESTAMP WITH TIME ZONE,    -- extracted from the Chromium DB
    times_used INTEGER,                                 -- extracted from the Chromium DB

    encryption_type TEXT,                               -- carved from the `password_value_enc` bytes - dpapi, key, or abe (app-bound-encryption)
    masterkey_guid UUID,                                -- if encryption_type == dpapi, associated masterkey GUID
    state_key_id INTEGER,                               -- if encryption_type != dpapi, linked to "id" in `chromium.state_keys`
    is_decrypted BOOLEAN,
    password_value_enc BYTEA,                           -- extracted from the Chromium DB `password_value` field
    password_value_dec TEXT,

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    FOREIGN KEY (state_key_id) REFERENCES chromium.state_keys(id) ON DELETE SET NULL,
    UNIQUE (source, username, browser, origin_url, username_value)
);

-- "cookies" table in "Cookies" file
CREATE TABLE IF NOT EXISTS chromium.cookies (
    id SERIAL PRIMARY KEY,
    originating_object_id UUID,
    agent_id VARCHAR(255),
    source VARCHAR(1000),
    project VARCHAR(255),
    username TEXT,                                      -- username extracted from user data directory, if applicable
    browser TEXT,                                       -- browser name extracted from user data directory, if applicable

    host_key TEXT,                                      -- extracted from the Chromium DB
    name TEXT,                                          -- extracted from the Chromium DB
    path TEXT,                                          -- extracted from the Chromium DB
    creation_utc TIMESTAMP WITH TIME ZONE,              -- extracted from the Chromium DB
    expires_utc TIMESTAMP WITH TIME ZONE,               -- extracted from the Chromium DB
    last_access_utc TIMESTAMP WITH TIME ZONE,           -- extracted from the Chromium DB
    last_update_utc TIMESTAMP WITH TIME ZONE,           -- extracted from the Chromium DB
    is_secure BOOLEAN,                                  -- extracted from the Chromium DB
    is_httponly BOOLEAN,                                -- extracted from the Chromium DB
    is_persistent BOOLEAN,                              -- extracted from the Chromium DB
    samesite TEXT,                                      -- extracted from the Chromium DB, translated from int
    source_port INTEGER,                                -- extracted from the Chromium DB

    encryption_type TEXT,                               -- carved from the `encrypted_value` field - dpapi, key, or abe (app-bound-encryption)
    masterkey_guid UUID,                                -- if encryption_type == dpapi, associated masterkey GUID
    state_key_id INTEGER,                               -- if encryption_type != dpapi, linked to "id" in `chromium.state_keys`
    is_decrypted BOOLEAN,
    value_enc BYTEA,                                    -- extracted from the Chromium DB `encrypted_value` field
    value_dec TEXT,

    FOREIGN KEY (originating_object_id) REFERENCES files_enriched(object_id) ON DELETE CASCADE,
    FOREIGN KEY (state_key_id) REFERENCES chromium.state_keys(id) ON DELETE SET NULL,
    UNIQUE (source, username, browser, host_key, name, path)
);

-- DPAPI tables
CREATE SCHEMA dpapi;

CREATE TABLE IF NOT EXISTS dpapi.masterkeys (
    id SERIAL PRIMARY KEY,
    guid TEXT UNIQUE NOT NULL,
    encrypted_key_usercred BYTEA,
    encrypted_key_backup BYTEA,
    plaintext_key BYTEA,
    plaintext_key_sha1 BYTEA,
    backup_key_guid TEXT,
    masterkey_type TEXT DEFAULT 'unknown',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dpapi.domain_backup_keys (
    id SERIAL PRIMARY KEY,
    guid TEXT UNIQUE NOT NULL,
    key_data BYTEA NOT NULL,
    domain_controller TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dpapi.system_credentials (
    id SERIAL PRIMARY KEY,
    user_key BYTEA NOT NULL,
    machine_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_key, machine_key)
);

-- Create triggers for DPAPI tables
CREATE OR REPLACE TRIGGER update_dpapi_masterkeys_updated_at
    BEFORE UPDATE ON dpapi.masterkeys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_dpapi_domain_backup_keys_updated_at
    BEFORE UPDATE ON dpapi.domain_backup_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_dpapi_system_credentials_updated_at
    BEFORE UPDATE ON dpapi.system_credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();