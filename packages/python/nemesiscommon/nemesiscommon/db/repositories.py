from abc import ABC, abstractmethod
from typing import Generic, TypeVar
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from nemesiscommon.db.models import AgentHostMapping, NamedPipe, Process

logger = structlog.get_logger(module=__name__)
T = TypeVar('T')


class IGenericRepository(ABC, Generic[T]):

    @abstractmethod
    async def add(self, entity: T) -> T:
        pass

    @abstractmethod
    async def get_by_id(self, id: UUID) -> T:
        pass


class NamedPipeRepository(IGenericRepository[NamedPipe]):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, entity: NamedPipe) -> NamedPipe:
        self.session.add(entity)
        await self.session.commit()
        await self.session.refresh(entity)
        return entity

    async def get_by_id(self, id: int) -> NamedPipe | None:
        q = select(NamedPipe).filter(NamedPipe.unique_db_id == id)
        result = await self.session.execute(q)
        return result.scalars().first()


class ProcessRepository(IGenericRepository[Process]):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, entity: Process) -> Process:
        self.session.add(entity)
        await self.session.commit()
        await self.session.refresh(entity)
        return entity

    async def get_by_id(self, id: int) -> Process | None:
        q = select(Process).filter(Process.unique_db_id == id)
        result = await self.session.execute(q)
        return result.scalars().first()

# class RegistryValueRepository(IGenericRepository[]):
#     def __init__(self, session: AsyncSession) -> None:
#         self.session = session

#     async def add(self, entity: NamedPipe) -> NamedPipe:
#         self.session.add(entity)
#         await self.session.commit()
#         await self.session.refresh(entity)
#         return entity

#     async def get_by_id(self, id: int) -> NamedPipe | None:
#         q = select(NamedPipe).filter(NamedPipe.unique_db_id == id)
#         result = await self.session.execute(q)
#         return result.scalars().first()

class AgentHostMappingRepository(IGenericRepository[AgentHostMapping]):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, entity: AgentHostMapping) -> AgentHostMapping:
        self.session.add(entity)
        await self.session.commit()
        await self.session.refresh(entity)
        return entity

    async def get_by_id(self, id: int) -> AgentHostMapping | None:
        q = select(AgentHostMapping).filter(AgentHostMapping.id == id)
        result = await self.session.execute(q)
        return result.scalars().first()

    async def update(self, entity: AgentHostMapping) -> None:
        result = await self.session.execute(
            select(AgentHostMapping).where(AgentHostMapping.id == entity.id)
        )
        mapping = result.scalars().first()

        if not mapping:
            raise Exception(f"AgentHostMapping update with id {entity.id} not found")

        mapping.ip_address = entity.ip_address
        mapping.shortname = entity.shortname
        mapping.longname = entity.longname

        await self.session.commit()