from typing import Any, Protocol

from src.domain.entities.gateway_models import TokenContext, UpstreamResponse


class AuthIntrospectionClientPort(Protocol):
    """Contrato para Consultar /introspect no Servidor de Autorização."""

    async def introspect(self, bearer_token: str) -> TokenContext: ...


class ResourceProxyClientPort(Protocol):
    """Contrato para Encaminhar requisição autorizada ao Resource Server."""

    async def forward_request(
        self,
        method: str,
        path: str,
        token_context: TokenContext,
        json_body: dict[str, Any] | None = None,
    ) -> UpstreamResponse: ...
