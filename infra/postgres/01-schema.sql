CREATE EXTENSION IF NOT EXISTS pg_trgm;

-----------------------
-- FILES
-----------------------
CREATE TABLE IF NOT EXISTS files (
    object_id UUID PRIMARY KEY,
    agent_id VARCHAR(255),
    project VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE,
    expiration TIMESTAMP WITH TIME ZONE,
    path TEXT,
    originating_object_id UUID,
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
    max_results integer DEFAULT 100
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
