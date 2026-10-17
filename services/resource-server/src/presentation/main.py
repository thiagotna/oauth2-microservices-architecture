from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from src.domain.exceptions.resource_errors import ResourceDomainError
from src.infrastructure.config.settings import get_settings
from src.infrastructure.database.models import (
    Base,
    ProtectedResourceModel,
    create_session_factory,
)
from src.presentation.api.resource_router import router as resource_router

DEMO_OWNER_ID = "11111111-1111-1111-1111-111111111111"
DEMO_RESOURCE_UUID = UUID("33333333-3333-3333-3333-333333333333")


async def _init_resource_db_and_seed() -> None:
    """Cria a tabela no Banco de Dados de Recursos (resource-db) e popula um registro inicial."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = create_session_factory(settings.database_url)
    async with session_factory() as session:
        existing = await session.execute(
            select(ProtectedResourceModel).where(ProtectedResourceModel.id == DEMO_RESOURCE_UUID)
        )
        if not existing.scalar_one_or_none():
            session.add(
                ProtectedResourceModel(
                    id=DEMO_RESOURCE_UUID,
                    owner_id=DEMO_OWNER_ID,
                    title="Architecture Blueprint - OAuth 2.0 Zero-Trust",
                    content="Confidential system specification "
                    "protected by RFC 7662 Introspection.",
                    classification="TOP_SECRET",
                )
            )
            await session.commit()
    await engine.dispose()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    if settings.environment != "unit_test":
        await _init_resource_db_and_seed()
    yield


class HealthResponse(BaseModel):
    status: str
    service: str


app = FastAPI(
    title="OAuth 2.0 Resource Server (Protected APIs)",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(ResourceDomainError)
async def resource_error_handler(_request: Request, exc: ResourceDomainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.description},
    )


app.include_router(resource_router)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", service="resource-server")
