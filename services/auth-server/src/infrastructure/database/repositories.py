from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.models import OAuthClient, User
from src.infrastructure.database.models import OAuthClientModel, UserModel


class PostgresUserRepository:
    """Implementa UserRepositoryPort consultando o Banco de Dados de Usuários (auth-db)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(UserModel).where(UserModel.email == email)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def get_by_id(self, user_id: UUID) -> User | None:
        stmt = select(UserModel).where(UserModel.id == user_id)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return self._to_entity(row) if row else None

    @staticmethod
    def _to_entity(model: UserModel) -> User:
        return User(
            id=model.id,
            email=model.email,
            password_hash=model.password_hash,
            is_active=model.is_active,
            created_at=model.created_at,
        )


class PostgresClientRepository:
    """Implementa ClientRepositoryPort consultando clientes OAuth no auth-db."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_client_id(self, client_id: str) -> OAuthClient | None:
        stmt = select(OAuthClientModel).where(OAuthClientModel.client_id == client_id)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if not row:
            return None

        return OAuthClient(
            id=row.id,
            client_id=row.client_id,
            client_secret_hash=row.client_secret_hash,
            name=row.name,
            redirect_uris=tuple(
                uri.strip() for uri in row.redirect_uris_csv.split(",") if uri.strip()
            ),
            allowed_scopes=tuple(s.strip() for s in row.allowed_scopes_csv.split(",") if s.strip()),
            allowed_grant_types=tuple(
                g.strip() for g in row.allowed_grant_types_csv.split(",") if g.strip()
            ),
            is_confidential=row.is_confidential,
        )
