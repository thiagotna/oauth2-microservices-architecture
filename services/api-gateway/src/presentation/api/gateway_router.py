from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse

from src.application.use_cases.proxy_use_case import AuthorizeAndProxyUseCase
from src.domain.exceptions.gateway_errors import MissingOrInvalidTokenError
from src.infrastructure.config.settings import GatewaySettings, get_settings
from src.infrastructure.http.http_adapters import (
    HttpxAuthIntrospectionAdapter,
    HttpxResourceProxyAdapter,
)

router = APIRouter(prefix="/api/v1/resources", tags=["API Gateway Proxy (Steps 4 to 8)"])


def get_proxy_use_case(
    settings: Annotated[GatewaySettings, Depends(get_settings)],
) -> AuthorizeAndProxyUseCase:
    introspection_adapter = HttpxAuthIntrospectionAdapter(
        introspect_url=settings.auth_server_introspect_url,
        client_id=settings.gateway_client_id,
        client_secret=settings.gateway_client_secret,
        timeout=settings.http_timeout_seconds,
    )
    resource_adapter = HttpxResourceProxyAdapter(
        resource_base_url=settings.resource_server_base_url,
        timeout=settings.http_timeout_seconds,
    )
    return AuthorizeAndProxyUseCase(introspection_adapter, resource_adapter)


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise MissingOrInvalidTokenError(
            "Missing or malformed Authorization: Bearer <token> header."
        )
    return authorization.removeprefix("Bearer ").strip()


@router.get("")
async def proxy_list_resources(
    use_case: Annotated[AuthorizeAndProxyUseCase, Depends(get_proxy_use_case)],
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Passo 4 -> 5 -> 6 -> 7 -> 8: Lista recursos protegidos exigindo escopo 'read:resources'."""
    token = _extract_bearer_token(authorization)
    upstream = await use_case.execute(
        bearer_token=token,
        method="GET",
        path="/api/v1/resources",
        required_scope="read:resources",
    )
    return JSONResponse(status_code=upstream.status_code, content=upstream.body)


@router.post("")
async def proxy_create_resource(
    payload: dict[str, Any],
    use_case: Annotated[AuthorizeAndProxyUseCase, Depends(get_proxy_use_case)],
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Passo 4 -> 5 -> 6 -> 7 -> 8: Cria recurso protegido exigindo escopo 'write:resources'."""
    token = _extract_bearer_token(authorization)
    upstream = await use_case.execute(
        bearer_token=token,
        method="POST",
        path="/api/v1/resources",
        required_scope="write:resources",
        json_body=payload,
    )
    return JSONResponse(status_code=upstream.status_code, content=upstream.body)
