from typing import Any

import pytest

from src.application.use_cases.proxy_use_case import AuthorizeAndProxyUseCase
from src.domain.entities.gateway_models import TokenContext, UpstreamResponse
from src.domain.exceptions.gateway_errors import (
    InsufficientScopeError,
    MissingOrInvalidTokenError,
)
from src.presentation.main import HealthResponse, app


class FakeIntrospectionClient:
    def __init__(self, context: TokenContext) -> None:
        self._context = context

    async def introspect(self, bearer_token: str) -> TokenContext:
        if bearer_token == "valid_token":
            return self._context
        return TokenContext(active=False)


class FakeResourceProxyClient:
    async def forward_request(
        self,
        method: str,
        path: str,
        token_context: TokenContext,
        json_body: dict[str, Any] | None = None,
    ) -> UpstreamResponse:
        return UpstreamResponse(
            status_code=200,
            body={"owner": token_context.sub, "method": method, "path": path},
            headers={"content-type": "application/json"},
        )


def test_gateway_app_initialized() -> None:
    assert app.title == "OAuth 2.0 API Gateway"
    resp = HealthResponse(status="healthy", service="api-gateway")
    assert resp.status == "healthy"


@pytest.mark.asyncio
async def test_gateway_allows_active_token_and_forwards_step_5_to_8() -> None:
    ctx = TokenContext(
        active=True,
        sub="11111111-1111-1111-1111-111111111111",
        client_id="web_app",
        scope="read:resources",
    )
    use_case = AuthorizeAndProxyUseCase(FakeIntrospectionClient(ctx), FakeResourceProxyClient())

    response = await use_case.execute(
        bearer_token="valid_token",
        method="GET",
        path="/api/v1/resources",
        required_scope="read:resources",
    )
    assert response.status_code == 200
    assert response.body["owner"] == "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_gateway_rejects_inactive_token_on_step_5() -> None:
    ctx = TokenContext(active=False)
    use_case = AuthorizeAndProxyUseCase(FakeIntrospectionClient(ctx), FakeResourceProxyClient())

    with pytest.raises(MissingOrInvalidTokenError):
        await use_case.execute(
            bearer_token="expired_or_revoked_token",
            method="GET",
            path="/api/v1/resources",
            required_scope="read:resources",
        )


@pytest.mark.asyncio
async def test_gateway_rejects_insufficient_scope() -> None:
    ctx = TokenContext(
        active=True,
        sub="11111111-1111-1111-1111-111111111111",
        client_id="web_app",
        scope="read:resources",
    )
    use_case = AuthorizeAndProxyUseCase(FakeIntrospectionClient(ctx), FakeResourceProxyClient())

    with pytest.raises(InsufficientScopeError):
        await use_case.execute(
            bearer_token="valid_token",
            method="POST",
            path="/api/v1/resources",
            required_scope="write:resources",
        )
