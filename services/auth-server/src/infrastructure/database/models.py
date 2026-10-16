from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(AsyncAttrs, DeclarativeBase):
    pass


class UserModel(Base):
    """Tabela de Usuários no auth-db (Passo 2 do Fluxograma)."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class OAuthClientModel(Base):
    """Tabela de Aplicações Clientes OAuth 2.0 registradas no auth-db."""

    __tablename__ = "oauth_clients"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    redirect_uris_csv: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_scopes_csv: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_grant_types_csv: Mapped[str] = mapped_column(Text, nullable=False)
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class RefreshTokenModel(Base):
    """Tabela de Refresh Tokens emitidos para suporte a rotação e auditoria."""

    __tablename__ = "refresh_tokens"

    token_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    client_id: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_session_factory(database_url: str) -> async_sessionmaker:  # type: ignore[type-arg]
    engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False)
