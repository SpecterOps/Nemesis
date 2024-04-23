# Standard Libraries

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dependency_injector import containers, providers
from nemesiscommon.db.database import Database
from nemesiscommon.db.repositories import ProcessRepository
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# 3rd Party Libraries
import enrichment.settings as settings
from enrichment.settings import config

engine = create_async_engine(str(config.postgres_async_connection_uri), echo=False)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


class DatabaseContainer(containers.DeclarativeContainer):
    # Use this if you want to pass settings to the providers below
    # Workaround for Pydantic2: https://github.com/ets-labs/python-dependency-injector/issues/755#issuecomment-1885607691
    config = providers.Configuration()
    json_config = settings.config.model_dump(mode="json")
    config.from_dict(json_config)

    db = providers.Singleton(Database, db_url=config.postgres_async_connection_uri)

    process_repository = providers.Factory(
        ProcessRepository,
        session=db.provided.session,
    )


@asynccontextmanager
async def get_async_session(
    engine: AsyncEngine = engine,
) -> AsyncGenerator[AsyncSession, None]:
    """Get a session to the database asynchronously."""
    async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session_maker() as session:
        yield session
