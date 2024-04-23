-- Stored Procedures
CREATE OR REPLACE FUNCTION f_register_agent_host(
    _project_id UUID,
    _message_timestamp TIMESTAMP,
    _expiration_date TIMESTAMP,
    _agent_id TEXT,
    _agent_type TEXT,
    _short_name TEXT,
    _long_name TEXT,
    _ip_address INET,
    OUT _host_id UUID,
    OUT _agent_row_id UUID
)
LANGUAGE plpgsql AS
$func$
BEGIN
    -- Check if the agent already already exists
    IF EXISTS (SELECT host_mapping_id, agent_id FROM agents WHERE project_id = _project_id AND agent_id = _agent_id AND agent_type = _agent_type) THEN
        -- RETURN (SELECT hostagents_row_id FROM agents WHERE project_id = _project_id AND agent_id = _agent_id AND agent_type = _agent_type);
        SELECT host_mapping_id, id FROM agents WHERE project_id = _project_id AND agent_id = _agent_id AND agent_type = _agent_type INTO _host_id, _agent_row_id;
    ELSE
        -- Agent doesn't exist, so create new host and agent
        INSERT INTO nemesis.agent_host_mappings (project_id, shortname, longname, ip_address)
        VALUES (_project_id, _short_name, _long_name, _ip_address)
        RETURNING id
        INTO _host_id;

        -- Typically bad idea to have this DO UPDATE on conflict, but should happen rarely
        -- See why at https://stackoverflow.com/a/42217872
        INSERT INTO agents (agent_id, agent_type, host_mapping_id, project_id)
        VALUES (_agent_id, _agent_type, _host_id, _project_id)
        ON CONFLICT (agent_id, agent_type, project_id)
        DO UPDATE SET agent_id=_agent_id
        RETURNING id
        INTO _agent_row_id;

        -- Return the new person ID
        -- RETURN _host_id;
    END IF;
END;
$func$;


-- Creates a project (if it doesn't exist) safely during concurrency
-- For reasons why and what this was derived from, see https://dba.stackexchange.com/questions/212580/concurrent-transactions-result-in-race-condition-with-unique-constraint-on-inser
CREATE OR REPLACE FUNCTION f_register_project(_name text, _creation_timestamp TIMESTAMP, _expiration_date TIMESTAMP) RETURNS UUID
LANGUAGE plpgsql AS
$func$
DECLARE
    _project_id UUID;
BEGIN
    LOOP
        SELECT id
        FROM   projects
        WHERE  name = _name
        FOR    UPDATE
        INTO   _project_id;

        EXIT WHEN FOUND;

        INSERT INTO projects  AS a (name, timestamp, expiration)
        VALUES (_name, _creation_timestamp, _expiration_date)
        ON     CONFLICT (name) DO NOTHING  -- (new?) _content is discarded
        RETURNING a.id
        INTO   _project_id;

        EXIT WHEN FOUND;
    END LOOP;

    RETURN _project_id;
END
$func$;