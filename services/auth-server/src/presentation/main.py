from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from src.domain.exceptions.oauth_errors import OAuthDomainError
from src.infrastructure.config.settings import get_settings
from src.infrastructure.database.models import (
    Base,
    OAuthClientModel,
    UserModel,
    create_session_factory,
)
from src.infrastructure.security.crypto_adapters import Argon2PasswordHasherAdapter
from src.presentation.api.v1.oauth_router import router as oauth_router

DEMO_USER_ID = UUID("11111111-1111-1111-1111-111111111111")
DEMO_CLIENT_UUID = UUID("22222222-2222-2222-2222-222222222222")


async def _init_db_and_seed() -> None:
    """Cria o schema no Banco de Dados de Utilizadores (auth-db) e popula dados iniciais."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = create_session_factory(settings.database_url)
    hasher = Argon2PasswordHasherAdapter()

    async with session_factory() as session:
        existing_user = await session.execute(
            select(UserModel).where(UserModel.email == "eng@architecture.dev")
        )
        if not existing_user.scalar_one_or_none():
            session.add(
                UserModel(
                    id=DEMO_USER_ID,
                    email="eng@architecture.dev",
                    password_hash=hasher.hash_secret("StrongPass!2026"),
                    is_active=True,
                )
            )

        existing_client = await session.execute(
            select(OAuthClientModel).where(OAuthClientModel.client_id == "web_app")
        )
        if not existing_client.scalar_one_or_none():
            session.add(
                OAuthClientModel(
                    id=DEMO_CLIENT_UUID,
                    client_id="web_app",
                    client_secret_hash=hasher.hash_secret("web_app_super_secret"),
                    name="Demo SPA / Web Client",
                    redirect_uris_csv="https://app.local/callback,http://localhost:3000/callback",
                    allowed_scopes_csv="read:resources,write:resources",
                    allowed_grant_types_csv="authorization_code,refresh_token,client_credentials",
                    is_confidential=True,
                )
            )

        await session.commit()
    await engine.dispose()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    if settings.environment != "unit_test":
        await _init_db_and_seed()
    yield


class HealthResponse(BaseModel):
    status: str
    service: str


app = FastAPI(
    title="OAuth 2.0 Authorization Server (IdP)",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(OAuthDomainError)
async def oauth_domain_exception_handler(_request: Request, exc: OAuthDomainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.description},
    )


app.include_router(oauth_router)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", service="auth-server")
