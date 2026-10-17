from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.resource_models import ProtectedResource
from src.infrastructure.database.models import ProtectedResourceModel


class PostgresProtectedResourceRepository:
    """Implementa ProtectedResourceRepositoryPort consultando o resource-db."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_by_owner(self, owner_id: str) -> list[ProtectedResource]:
        stmt = (
            select(ProtectedResourceModel)
            .where(ProtectedResourceModel.owner_id == owner_id)
            .order_by(ProtectedResourceModel.created_at.desc())
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [self._to_entity(r) for r in rows]

    async def create(
        self, owner_id: str, title: str, content: str, classification: str
    ) -> ProtectedResource:
        model = ProtectedResourceModel(
            owner_id=owner_id,
            title=title,
            content=content,
            classification=classification,
        )
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return self._to_entity(model)

    @staticmethod
    def _to_entity(model: ProtectedResourceModel) -> ProtectedResource:
        return ProtectedResource(
            id=model.id,
            owner_id=model.owner_id,
            title=model.title,
            content=model.content,
            classification=model.classification,
            created_at=model.created_at,
        )
