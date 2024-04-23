import asyncio
import datetime
import logging
import uuid

import sqlalchemy
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.schema import CreateSchema, DropSchema

import nemesiscommon.db.models as dbmodels  # noqa: F401

DATABASE_URL = "postgresql+asyncpg://nemesis:Qwerty12345@localhost:5432/nemesis"

engine = create_async_engine(DATABASE_URL, echo=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
metadata = sqlalchemy.MetaData("nemesis")
# alembic_cfg = AlembicConfig("alembic.ini")
# alembic_cfg.set_main_option("sqlalchemy.url", database_url)


async def init_db(schema_name: str, drop_existing_schema: bool):
    """Creates the schema and tables in the database for the SQLModel classes.
    If drop_existing_schema is True, the schema will be dropped and recreated if it already exists.
    If drop_existing_schema is False and the schema already exists, the function will do nothing.
    If drop_existing_schema is False and the schema does not exist, the function will create the schema and tables.

    Args:
        schema_name (str): Name of the schema the tables will be created in.
        drop_existing_schema (bool): Should the schema be dropped and recreated if it already exists?
    """

    with open("sql/stored_procs.sql") as f:
        sql = f.read()

    async with engine.connect() as conn:
        if drop_existing_schema:
            await conn.execute(DropSchema(name=schema_name, cascade=True, if_exists=True))

        # Set the timezone to UTC
        # connection.execute(statement=text("SET TIMEZONE='UTC'"))
        # connection.execute(statement=text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await conn.execute(CreateSchema(schema_name, if_not_exists=True))
        await conn.execute(statement=text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))  # Enable trigram-based indexes
        # await connection.execute(statement=text(sql))
        await conn.run_sync(dbmodels.Base.metadata.create_all)
        await conn.commit()

    try:
        async with async_session_maker() as session:
            await create_test_data(session)
        pass
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
        raise e


async def register_project(session: AsyncSession, project) -> int:
    """Registers a project in the database and returnts the id. If the project already exists, the id is returned."""

    out = await session.execute(
        text("SELECT f_register_project(:name, :creation_timestamp, :expiration_timestamp)"),
        params={
            "name": project.project_name,
            "creation_timestamp": project.timestamp,
            "expiration_timestamp": project.expiration,
        },
    )
    project_id = out.scalar()

    if project_id is None:
        raise Exception("Failed to register project: recieved null project ID")

    return project_id


async def create_test_data(session: AsyncSession):
    message1 = dbmodels.ApiDataMessage(message_bytes=b"Hello, World!", expiration=datetime.datetime.now())
    session.add_all([message1])

    # Create Projects
    now = datetime.datetime.now()
    one_year_away = now + datetime.timedelta(days=365)
    project1 = dbmodels.Project(
        name="project1",
        timestamp=now,
        expiration=one_year_away,
    )

    project2 = dbmodels.Project(
        name="project2",
        timestamp=now,
        expiration=one_year_away,
    )

    session.add_all([project1, project2])
    await session.commit()

    # Create AgentHostMappings
    host_agent1 = dbmodels.AgentHostMapping(
        shortname="HostA",
        longname="HostA.corp.local",
        ip_address="192.168.230.42",
        project_id=project1.id,
    )
    host_agent2 = dbmodels.AgentHostMapping(
        shortname="HostB",
        longname="HostB.corp.local",
        ip_address="192.168.230.43",
        project_id=project1.id,
    )

    session.add_all([host_agent1, host_agent2])
    await session.commit()

    host_agent3 = dbmodels.AgentHostMapping(
        shortname="HostB",
        longname="HostB.corp.local",
        ip_address="192.168.230.44",
        project_id=project1.id,
        host_id=host_agent2.host_id,  # Shares the same host as host_agent2
    )
    host_agent4 = dbmodels.AgentHostMapping(
        project_id=project2.id,
        # No host details (e.g., DNS beacon)
    )
    session.add_all([host_agent3, host_agent4])
    await session.commit()

    # Create Agents
    agent1 = dbmodels.Agent(
        agent_id="1234",
        agent_type="cobaltstrike",
        host_mapping_id=host_agent1.id,
        project_id=project1.id,
    )
    agent2 = dbmodels.Agent(
        agent_id="5678",
        agent_type="cobaltstrike",
        host_mapping_id=host_agent2.id,
        project_id=project1.id,
    )
    agent3 = dbmodels.Agent(
        agent_id="1ac389dc-6223-47e3-93d6-3850361dd0d7",
        agent_type="apollo",
        host_mapping_id=host_agent3.id,
        project_id=project1.id,
    )
    agent4 = dbmodels.Agent(
        agent_id="d3adb33f",
        agent_type="cobaltstrike",
        host_mapping_id=host_agent4.id,  # has no host details (e.g., DNS beacon)
        project_id=project2.id,
    )

    session.add_all([agent1, agent2, agent3, agent4])
    await session.commit()

    metadata = {
        "message_id": message1.message_id,
        "project_id": project1.id,
        "timestamp": now,
        "expiration": one_year_away,
        "agent_id": agent1.id,
        "operation": dbmodels.DataOperation.add,
        "host_id": host_agent1.id,
        "is_data_remote": False,
        "originating_object_id": None,
    }

    process1 = dbmodels.Process(
        **metadata,
        # Process data
        name="asdf.exe",
        process_id=1
    )
    filesystem_object1 = dbmodels.FileSystemObject(
        **metadata,
        # Filesystem data
        path="C:\\Windows\\System32\\asdf.exe",
        type=dbmodels.FileSystemObjectType.file,
        name="asdf.exe",
        extension="exe",
    )

    session.add_all([process1, filesystem_object1])
    await session.commit()

    filedata_enriched1 = dbmodels.FileDataEnriched(
        **metadata,
        # Enriched file data
        object_id=filesystem_object1.message_id,
        path=filesystem_object1.path,
        name=filesystem_object1.name,
        magic_type="PE32",
    )

    registry_object1 = dbmodels.RegistryObject(
        **metadata,
        # Registry data
        key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    )

    registry_object2 = dbmodels.RegistryObject(
        **metadata,
        # Registry data
        key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="test2",
        value_kind=1,
        value="test2.exe",
        tags=["autorun"],
    )

    service1 = dbmodels.Service(
        **metadata,
        # Data
        name="spooler"
    )

    named_pipe1 = dbmodels.NamedPipe(
        **metadata,
        # Named Pipe data
        name="asdf",
    )
    session.add_all([filedata_enriched1, registry_object1, registry_object2, service1, named_pipe1])
    await session.commit()



    project_deprecated = {
        "expiration": one_year_away,
        "timestamp": now,
        "source": "COMP1",
        "project_id": project1.id
    }
    agent_and_unique_id = {
        "agent_id": "12345",
        "unique_db_id": uuid.uuid4()
    }

    # Check DPAPI constraints
    unencrypted_blob_bytes = dbmodels.DpapiBlob(
        **project_deprecated,
        **agent_and_unique_id,
        # DPAPI Blob data
        masterkey_guid=uuid.uuid4(),
        is_file=False,
        is_decrypted=False,
        enc_data_bytes=b"asdf",
    )
    unencrypted_blob_file = dbmodels.DpapiBlob(
        **project_deprecated,
        **agent_and_unique_id,
        # DPAPI Blob data
        masterkey_guid=uuid.uuid4(),
        is_file=True,
        is_decrypted=False,
        enc_data_object_id=uuid.uuid4(),
    )
    decrytped_blob_bytes = dbmodels.DpapiBlob(
        **project_deprecated,
        **agent_and_unique_id,
        # DPAPI Blob data
        masterkey_guid=uuid.uuid4(),
        is_file=False,
        is_decrypted=True,
        enc_data_bytes=b"asdf",
        dec_data_bytes=b"asdf",
    )
    decrypted_blob_file = dbmodels.DpapiBlob(
        **project_deprecated,
        **agent_and_unique_id,
        # DPAPI Blob data
        masterkey_guid=uuid.uuid4(),
        is_file=True,
        is_decrypted=True,
        enc_data_object_id=uuid.uuid4(),
        dec_data_object_id=uuid.uuid4(),
    )

    session.add_all([unencrypted_blob_bytes, unencrypted_blob_file, decrytped_blob_bytes, decrypted_blob_file])
    await session.commit()

    # Dpapi Backup/masterkeys
    dpapi_domain_backup_key = dbmodels.DpapiDomainBackupKey(
        **project_deprecated,
        **agent_and_unique_id,
        domain_backupkey_guid=uuid.uuid4(),
        domain_controller="DC01",
        domain_backupkey_bytes=b"asdf"
    )

    dpapi_masterkey = dbmodels.DpapiMasterKeys(
        **project_deprecated,
        **agent_and_unique_id,
        masterkey_guid=uuid.uuid4(),
        masterkey_bytes=b"asdf"
    )
    session.add_all([dpapi_domain_backup_key, dpapi_masterkey])
    await session.commit()

    # Chromium
    chromium_history = dbmodels.ChromiumHistoryEntry(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Chromium history
        agent_id="beacon",
        url="https://www.google.com",
        originating_object_id=uuid.uuid4(),
        user_data_directory="itadmin",
        title="Google",
        visit_count=1,
        typed_count=1,
        last_visit_time=now,
    )
    chromium_download = dbmodels.ChromiumDownload(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Chromium history
        agent_id="12345",
        originating_object_id=uuid.uuid4(),
        download_path="C:\\Users\\itadmin\\Downloads\\file.exe",
        user_data_directory="itadmin",
    )
    chromium_login = dbmodels.ChromiumLogin(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Chromium history
        agent_id="12345",
        originating_object_id=uuid.uuid4(),
        user_data_directory="itadmin",
        origin_url="https://www.google.com",
        username_value="itadmin",
    )

    chromium_cookies = dbmodels.ChromiumCookie(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        originating_object_id=uuid.uuid4(),
        user_data_directory="itadmin",
        host_key="asdf",
        name="asdf",
        path="/",
    )
    chromium_state_key = dbmodels.ChromiumStateFile(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        originating_object_id=uuid.uuid4(),
        key_bytes_enc=b"asdf",
        app_bound_fixed_data_enc=b"asdf",
        key_bytes_dec=b"asdf",
        app_bound_fixed_data_dec=b"asdf",
    )
    session.add_all([chromium_history, chromium_download, chromium_login, chromium_cookies, chromium_state_key])
    await session.commit()

    # Slack
    slack_download = dbmodels.SlackDownload(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        originating_object_id=uuid.uuid4(),
        workspace_id="asdf",
        download_id="asdf",
    )
    slack_workspace = dbmodels.SlackWorkspace(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        originating_object_id=None,
    )
    session.add_all([slack_download, slack_workspace])
    await session.commit()

    # Auth/credential data
    extracted_hash = dbmodels.ExtractedHash(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        hash_value="asdf",
    )
    authentication_data = dbmodels.AuthenticationData(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
    )
    session.add_all([extracted_hash, authentication_data])
    await session.commit()

    # Host/agent data
    host_deprecated = dbmodels.HostDEPRECATED(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        hostname="asdf"
    )
    session.add(host_deprecated)
    await session.commit()
    agent_deprecated = dbmodels.AgentsDEPRECATED(
        # ProjectDEPRECATED
        expiration=one_year_away,
        timestamp=now,
        source="COMP1",
        project_id=project1.id,

        # Data
        agent_id="12345",
        agent_type="beacon",
    )
    session.add(agent_deprecated)
    await session.commit()

    # Triage/notes
    triage = dbmodels.Triage(
        unique_db_id = uuid.uuid4(),
        expiration = one_year_away,
    )
    notes = dbmodels.Notes(
        unique_db_id = uuid.uuid4(),
        expiration = one_year_away,
    )
    session.add_all([triage, notes])
    await session.commit()


    print("\nDONE!")


async def amain():
    await init_db("nemesis", True)


loop = asyncio.get_event_loop()
try:
    task = amain()
    loop.run_until_complete(task)
except asyncio.exceptions.CancelledError:
    logging.debug("Primary App asyncio task cancelled. Application is shutting down.")