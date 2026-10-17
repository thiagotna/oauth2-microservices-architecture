from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.application.use_cases.resource_use_cases import (
    CreateProtectedResourceUseCase,
    ListProtectedResourcesUseCase,
)
from src.domain.entities.resource_models import ProtectedResource
from src.domain.exceptions.resource_errors import MissingIdentityContextError
from src.presentation.main import HealthResponse, app


class InMemoryProtectedResourceRepo:
    def __init__(self) -> None:
        self.items: list[ProtectedResource] = []

    async def list_by_owner(self, owner_id: str) -> list[ProtectedResource]:
        return [item for item in self.items if item.owner_id == owner_id]

    async def create(
        self, owner_id: str, title: str, content: str, classification: str
    ) -> ProtectedResource:
        new_item = ProtectedResource(
            id=uuid4(),
            owner_id=owner_id,
            title=title,
            content=content,
            classification=classification,
            created_at=datetime.now(UTC),
        )
        self.items.append(new_item)
        return new_item


def test_resource_app_initialized() -> None:
    assert app.title == "OAuth 2.0 Resource Server (Protected APIs)"
    resp = HealthResponse(status="healthy", service="resource-server")
    assert resp.status == "healthy"


@pytest.mark.asyncio
async def test_create_and_list_protected_resources_steps_6_and_7() -> None:
    repo = InMemoryProtectedResourceRepo()
    create_uc = CreateProtectedResourceUseCase(repo)
    list_uc = ListProtectedResourcesUseCase(repo)

    owner = "11111111-1111-1111-1111-111111111111"
    created = await create_uc.execute(
        owner_id=owner,
        title="Financial Audit Report",
        content="Q4 Revenue Data",
        classification="CONFIDENTIAL",
    )
    assert created.title == "Financial Audit Report"

    resources = await list_uc.execute(owner_id=owner)
    assert len(resources) == 1
    assert resources[0].owner_id == owner


@pytest.mark.asyncio
async def test_resource_use_case_rejects_missing_identity_header() -> None:
    repo = InMemoryProtectedResourceRepo()
    list_uc = ListProtectedResourcesUseCase(repo)

    with pytest.raises(MissingIdentityContextError):
        await list_uc.execute(owner_id="   ")
