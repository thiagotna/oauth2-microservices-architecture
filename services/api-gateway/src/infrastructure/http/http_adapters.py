from typing import Any

import httpx

from src.domain.entities.gateway_models import TokenContext, UpstreamResponse
from src.domain.exceptions.gateway_errors import UpstreamUnavailableError


class HttpxAuthIntrospectionAdapter:
    """Executa o chamado ao endpoint /introspect do Servidor de Autorização."""

    def __init__(
        self,
        introspect_url: str,
        client_id: str,
        client_secret: str,
        timeout: float = 5.0,
    ) -> None:
        self._introspect_url = introspect_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout

    async def introspect(self, bearer_token: str) -> TokenContext:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._introspect_url,
                    data={"token": bearer_token},
                    auth=(self._client_id, self._client_secret),
                )
                if response.status_code != 200:
                    return TokenContext(active=False)

                payload: dict[str, Any] = response.json()
                return TokenContext(
                    active=bool(payload.get("active", False)),
                    sub=str(payload["sub"]) if payload.get("sub") else None,
                    client_id=str(payload["client_id"]) if payload.get("client_id") else None,
                    scope=str(payload["scope"]) if payload.get("scope") else None,
                )
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError(
                "Authorization Server introspection unreachable."
            ) from exc


class HttpxResourceProxyAdapter:
    """Executa os Passos 6 e 7 encaminhando a chamada autorizada ao Servidor de Recursos."""

    def __init__(self, resource_base_url: str, timeout: float = 5.0) -> None:
        self._base_url = resource_base_url.rstrip("/")
        self._timeout = timeout

    async def forward_request(
        self,
        method: str,
        path: str,
        token_context: TokenContext,
        json_body: dict[str, Any] | None = None,
    ) -> UpstreamResponse:
        url = f"{self._base_url}/{path.lstrip('/')}"
        # Propagação de identidade confiável para a rede interna (Zero-Trust Context)
        headers: dict[str, str] = {
            "X-User-Id": token_context.sub or "",
            "X-Client-Id": token_context.client_id or "",
            "X-OAuth-Scopes": token_context.scope or "",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_body,
                )
                body = response.json() if response.content else {}
                return UpstreamResponse(
                    status_code=response.status_code,
                    body=body,
                    headers={
                        "content-type": response.headers.get("content-type", "application/json")
                    },
                )
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError("Resource Server unreachable.") from exc
