from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.use_cases.resource_use_cases import (
    CreateProtectedResourceUseCase,
    ListProtectedResourcesUseCase,
)
from src.infrastructure.config.settings import get_settings
from src.infrastructure.database.models import create_session_factory
from src.infrastructure.database.repositories import PostgresProtectedResourceRepository

router = APIRouter(prefix="/api/v1/resources", tags=["Protected Resources (Steps 6 & 7)"])

_settings = get_settings()
_session_factory = create_session_factory(_settings.database_url)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with _session_factory() as session:
        yield session


class CreateResourceSchema(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    content: str = Field(..., min_length=3)
    classification: str = Field(default="CONFIDENTIAL")


class ResourceItemSchema(BaseModel):
    id: str
    owner_id: str
    title: str
    content: str
    classification: str


class ResourceListResponseSchema(BaseModel):
    owner_id: str
    scopes_granted: list[str]
    items: list[ResourceItemSchema]


@router.get("", response_model=ResourceListResponseSchema)
async def list_resources(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    x_user_id: Annotated[str, Header()] = "",
    x_oauth_scopes: Annotated[str, Header()] = "",
) -> ResourceListResponseSchema:
    """Passo 6 e 7: Recebe requisição autorizada do Gateway, consulta o resource-db e retorna."""
    use_case = ListProtectedResourcesUseCase(PostgresProtectedResourceRepository(session))
    resources = await use_case.execute(owner_id=x_user_id)
    return ResourceListResponseSchema(
        owner_id=x_user_id,
        scopes_granted=x_oauth_scopes.split() if x_oauth_scopes else [],
        items=[
            ResourceItemSchema(
                id=str(item.id),
                owner_id=item.owner_id,
                title=item.title,
                content=item.content,
                classification=item.classification,
            )
            for item in resources
        ],
    )


@router.post("", response_model=ResourceItemSchema, status_code=201)
async def create_resource(
    payload: CreateResourceSchema,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    x_user_id: Annotated[str, Header()] = "",
) -> ResourceItemSchema:
    """Passo 6 e 7: Cria um novo registro no Banco de Dados de Recursos."""
    use_case = CreateProtectedResourceUseCase(PostgresProtectedResourceRepository(session))
    created = await use_case.execute(
        owner_id=x_user_id,
        title=payload.title,
        content=payload.content,
        classification=payload.classification,
    )
    return ResourceItemSchema(
        id=str(created.id),
        owner_id=created.owner_id,
        title=created.title,
        content=created.content,
        classification=created.classification,
    )
