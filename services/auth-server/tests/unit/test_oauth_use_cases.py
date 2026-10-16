from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from src.application.dtos.oauth_dtos import AuthorizeRequestDTO, TokenExchangeRequestDTO
from src.application.strategies.grant_strategies import (
    AuthorizationCodeGrantStrategy,
    GrantStrategyFactory,
)
from src.application.use_cases.oauth_use_cases import (
    AuthorizeUserUseCase,
    IntrospectTokenUseCase,
    IssueTokenUseCase,
)
from src.domain.entities.models import OAuthClient, User
from src.domain.entities.tokens import AuthorizationCode, IntrospectionResult, RefreshTokenData
from src.domain.exceptions.oauth_errors import AccessDeniedError, InvalidGrantError


class InMemoryUserRepo:
    def __init__(self, user: User) -> None:
        self._user = user

    async def get_by_email(self, email: str) -> User | None:
        return self._user if self._user.email == email else None

    async def get_by_id(self, user_id: UUID) -> User | None:
        return self._user if self._user.id == user_id else None


class InMemoryClientRepo:
    def __init__(self, client: OAuthClient) -> None:
        self._client = client

    async def get_by_client_id(self, client_id: str) -> OAuthClient | None:
        return self._client if self._client.client_id == client_id else None


class InMemoryAuthCodeCache:
    def __init__(self) -> None:
        self.store: dict[str, AuthorizationCode] = {}

    async def save(self, auth_code: AuthorizationCode, ttl_seconds: int) -> None:
        self.store[auth_code.code] = auth_code

    async def consume(self, code: str) -> AuthorizationCode | None:
        return self.store.pop(code, None)


class InMemoryRevocationRepo:
    def __init__(self) -> None:
        self.refresh_tokens: dict[str, RefreshTokenData] = {}
        self.revoked_jtis: set[str] = set()

    async def save_refresh_token(self, token_data: RefreshTokenData) -> None:
        self.refresh_tokens[token_data.token_id] = token_data

    async def get_refresh_token(self, token_id: str) -> RefreshTokenData | None:
        return self.refresh_tokens.get(token_id)

    async def revoke_refresh_token(self, token_id: str) -> None:
        if token_id in self.refresh_tokens:
            old = self.refresh_tokens[token_id]
            self.refresh_tokens[token_id] = RefreshTokenData(
                token_id=old.token_id,
                user_id=old.user_id,
                client_id=old.client_id,
                scope=old.scope,
                is_revoked=True,
                expires_at=old.expires_at,
            )

    async def revoke_access_token_jti(self, jti: str, ttl_seconds: int) -> None:
        self.revoked_jtis.add(jti)

    async def is_access_token_revoked(self, jti: str) -> bool:
        return jti in self.revoked_jtis


class FakeSecurityAdapter:
    def hash_secret(self, plain_secret: str) -> str:
        return f"hashed_{plain_secret}"

    def verify_secret(self, plain_secret: str, hashed_secret: str) -> bool:
        return hashed_secret == f"hashed_{plain_secret}"

    def verify_challenge(
        self, code_verifier: str, code_challenge: str, method: str = "S256"
    ) -> bool:
        return code_challenge == f"challenge_{code_verifier}" and method == "S256"

    def create_access_token(
        self, subject: str, client_id: str, scope: str, user_id: UUID | None = None
    ) -> tuple[str, int, str]:
        return f"jwt_for_{subject}", 900, "jti_123"

    def decode_and_verify(self, token: str) -> IntrospectionResult:
        if token.startswith("jwt_for_"):
            sub = token.replace("jwt_for_", "")
            return IntrospectionResult(
                active=True, scope="read:resources", client_id="web_app", sub=sub, jti="jti_123"
            )
        return IntrospectionResult(active=False)


@pytest.mark.asyncio
async def test_full_oauth_flow_steps_1_2_3_and_5() -> None:
    user = User(
        id=uuid4(),
        email="eng@architecture.dev",
        password_hash="hashed_correct_pass",
        is_active=True,
        created_at=datetime.now(UTC),
    )
    client = OAuthClient(
        id=uuid4(),
        client_id="web_app",
        client_secret_hash="hashed_client_secret",
        name="Web App",
        redirect_uris=("https://app.local/callback",),
        allowed_scopes=("read:resources", "write:resources"),
        allowed_grant_types=("authorization_code", "refresh_token"),
        is_confidential=True,
    )

    user_repo = InMemoryUserRepo(user)
    client_repo = InMemoryClientRepo(client)
    code_cache = InMemoryAuthCodeCache()
    revocation_repo = InMemoryRevocationRepo()
    security = FakeSecurityAdapter()

    # Passos 1 e 2: Solicitação de Autorização e Autenticação do Usuário
    authorize_uc = AuthorizeUserUseCase(user_repo, client_repo, code_cache, security)
    auth_resp = await authorize_uc.execute(
        AuthorizeRequestDTO(
            client_id="web_app",
            redirect_uri="https://app.local/callback",
            scope="read:resources",
            code_challenge="challenge_my_secret_verifier",
            code_challenge_method="S256",
            user_email="eng@architecture.dev",
            user_password="correct_pass",
            state="xyz",
        )
    )
    assert auth_resp.code != ""
    assert auth_resp.state == "xyz"

    # Passo 3: Troca do Authorization Code + PKCE pelo Access Token
    auth_code_strategy = AuthorizationCodeGrantStrategy(
        code_cache, revocation_repo, security, security
    )
    factory = GrantStrategyFactory({"authorization_code": auth_code_strategy})
    issue_token_uc = IssueTokenUseCase(client_repo, security, factory)

    token_pair = await issue_token_uc.execute(
        TokenExchangeRequestDTO(
            grant_type="authorization_code",
            client_id="web_app",
            client_secret="client_secret",
            code=auth_resp.code,
            redirect_uri="https://app.local/callback",
            code_verifier="my_secret_verifier",
        )
    )
    assert token_pair.access_token == f"jwt_for_{user.id}"
    assert token_pair.refresh_token is not None

    # Garantia de Single-Use: tentar usar o mesmo código uma 2ª vez deve falhar!
    with pytest.raises(InvalidGrantError):
        await issue_token_uc.execute(
            TokenExchangeRequestDTO(
                grant_type="authorization_code",
                client_id="web_app",
                client_secret="client_secret",
                code=auth_resp.code,
                redirect_uri="https://app.local/callback",
                code_verifier="my_secret_verifier",
            )
        )

    # Passo 5: Validação do Token via Introspecção (Gateway -> Auth Server)
    introspect_uc = IntrospectTokenUseCase(security, revocation_repo)
    introspection = await introspect_uc.execute(token_pair.access_token)
    assert introspection.active is True
    assert introspection.sub == str(user.id)


@pytest.mark.asyncio
async def test_authorize_rejects_wrong_password() -> None:
    user = User(
        id=uuid4(),
        email="eng@architecture.dev",
        password_hash="hashed_correct_pass",
        is_active=True,
        created_at=datetime.now(UTC),
    )
    client = OAuthClient(
        id=uuid4(),
        client_id="web_app",
        client_secret_hash="hashed_secret",
        name="Web App",
        redirect_uris=("https://app.local/callback",),
        allowed_scopes=("read:resources",),
        allowed_grant_types=("authorization_code",),
        is_confidential=False,
    )
    authorize_uc = AuthorizeUserUseCase(
        InMemoryUserRepo(user),
        InMemoryClientRepo(client),
        InMemoryAuthCodeCache(),
        FakeSecurityAdapter(),
    )

    with pytest.raises(AccessDeniedError):
        await authorize_uc.execute(
            AuthorizeRequestDTO(
                client_id="web_app",
                redirect_uri="https://app.local/callback",
                scope="read:resources",
                code_challenge="challenge_123",
                code_challenge_method="S256",
                user_email="eng@architecture.dev",
                user_password="wrong_password",
            )
        )
