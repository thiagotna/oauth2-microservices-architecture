import base64
import hashlib
import secrets

import httpx
import pytest

AUTH_SERVER_URL = "http://auth-server:8001"
API_GATEWAY_URL = "http://api-gateway:8000"


def _generate_pkce_pair() -> tuple[str, str]:
    """Gera code_verifier e code_challenge S256 segundo a RFC 7636."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.mark.asyncio
async def test_complete_oauth2_flowchart_steps_1_to_8() -> None:
    """Valida em tempo real os Passos 1 a 8 do Fluxograma de Infraestrutura OAuth 2.0."""
    code_verifier, code_challenge = _generate_pkce_pair()

    async with httpx.AsyncClient(timeout=10.0) as client:
        # =====================================================================
        # PASSOS 1 e 2: Solicitação de Autorização + Autenticação no auth-db
        # =====================================================================
        auth_response = await client.post(
            f"{AUTH_SERVER_URL}/api/v1/oauth/authorize",
            json={
                "client_id": "web_app",
                "redirect_uri": "https://app.local/callback",
                "scope": "read:resources write:resources",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "user_email": "eng@architecture.dev",
                "user_password": "StrongPass!2026",
                "state": "e2e_state_999",
            },
        )
        assert auth_response.status_code == 200, auth_response.text
        auth_data = auth_response.json()
        assert "code" in auth_data
        assert auth_data["state"] == "e2e_state_999"
        authorization_code = auth_data["code"]

        # =====================================================================
        # PASSO 3: Troca do Authorization Code + PKCE pelo Access Token
        # =====================================================================
        token_response = await client.post(
            f"{AUTH_SERVER_URL}/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "web_app",
                "client_secret": "web_app_super_secret",
                "code": authorization_code,
                "redirect_uri": "https://app.local/callback",
                "code_verifier": code_verifier,
            },
        )
        assert token_response.status_code == 200, token_response.text
        token_data = token_response.json()
        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]
        assert token_data["token_type"] == "Bearer"
        assert access_token != ""
        assert refresh_token is not None

        # =====================================================================
        # PASSOS 4, 5, 6, 7 e 8:
        # 4. Cliente chama Gateway com Bearer Token
        # 5. Gateway valida token via Introspecção no Auth Server
        # 6. Gateway encaminha requisição ao Resource Server
        # 7. Resource Server consulta resource-db e retorna os dados
        # 8. Gateway entrega resposta ao Cliente
        # =====================================================================
        resource_list_resp = await client.get(
            f"{API_GATEWAY_URL}/api/v1/resources",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resource_list_resp.status_code == 200, resource_list_resp.text
        resources_payload = resource_list_resp.json()
        assert resources_payload["owner_id"] == "11111111-1111-1111-1111-111111111111"
        assert "read:resources" in resources_payload["scopes_granted"]
        assert len(resources_payload["items"]) >= 1

        # Cria um novo recurso protegido via Gateway (exigindo escopo write:resources)
        create_resp = await client.post(
            f"{API_GATEWAY_URL}/api/v1/resources",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "title": "E2E Verified Microservice Record",
                "content": "Created through Step 4 -> 5 -> 6 -> 7 -> 8 pipeline.",
                "classification": "RESTRICTED",
            },
        )
        assert create_resp.status_code == 201, create_resp.text
        created_item = create_resp.json()
        assert created_item["title"] == "E2E Verified Microservice Record"
        assert created_item["owner_id"] == "11111111-1111-1111-1111-111111111111"

        # =====================================================================
        # TESTE DE SEGURANÇA EXTRA: Token inválido deve ser barrado no Passo 5
        # =====================================================================
        unauthorized_resp = await client.get(
            f"{API_GATEWAY_URL}/api/v1/resources",
            headers={"Authorization": "Bearer forged_or_invalid_jwt_token"},
        )
        assert unauthorized_resp.status_code == 401
        assert unauthorized_resp.json()["error"] == "invalid_token"
