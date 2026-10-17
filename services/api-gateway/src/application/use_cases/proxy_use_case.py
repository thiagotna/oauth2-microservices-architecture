from typing import Any

from src.domain.entities.gateway_models import UpstreamResponse
from src.domain.exceptions.gateway_errors import (
    InsufficientScopeError,
    MissingOrInvalidTokenError,
)
from src.domain.ports.clients import AuthIntrospectionClientPort, ResourceProxyClientPort


class AuthorizeAndProxyUseCase:
    """Orquestra o Fluxograma Arquitetural no API Gateway."""

    def __init__(
        self,
        introspection_client: AuthIntrospectionClientPort,
        resource_proxy_client: ResourceProxyClientPort,
    ) -> None:
        self._introspection_client = introspection_client
        self._resource_proxy_client = resource_proxy_client

    async def execute(
        self,
        bearer_token: str,
        method: str,
        path: str,
        required_scope: str,
        json_body: dict[str, Any] | None = None,
    ) -> UpstreamResponse:
        if not bearer_token.strip():
            raise MissingOrInvalidTokenError("Empty Bearer token.")

        # Passo 5: Validação do Token via Introspecção no Servidor de Autorização
        token_context = await self._introspection_client.introspect(bearer_token)
        if not token_context.active:
            raise MissingOrInvalidTokenError("Token is inactive, expired, or revoked.")

        if not token_context.has_scope(required_scope):
            raise InsufficientScopeError(f"Required scope '{required_scope}' not granted.")

        # Passos 6 e 7: Encaminha requisição autorizada ao Servidor de Recursos e obtém dados
        return await self._resource_proxy_client.forward_request(
            method=method,
            path=path,
            token_context=token_context,
            json_body=json_body,
        )
