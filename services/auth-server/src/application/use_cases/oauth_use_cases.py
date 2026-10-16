import secrets
from datetime import UTC, datetime, timedelta

from src.application.dtos.oauth_dtos import (
    AuthorizeRequestDTO,
    AuthorizeResponseDTO,
    TokenExchangeRequestDTO,
)
from src.application.strategies.grant_strategies import GrantStrategyFactory
from src.domain.entities.tokens import AuthorizationCode, IntrospectionResult, TokenPair
from src.domain.exceptions.oauth_errors import (
    AccessDeniedError,
    InvalidClientError,
    InvalidGrantError,
    InvalidScopeError,
)
from src.domain.ports.repositories import (
    AuthCodeCachePort,
    ClientRepositoryPort,
    TokenRevocationPort,
    UserRepositoryPort,
)
from src.domain.ports.security import PasswordHasherPort, TokenSignerPort


class AuthorizeUserUseCase:
    """Executa os Passos 1 e 2 do Fluxograma: Solicitação de Autorização e Autenticação."""

    def __init__(
        self,
        user_repo: UserRepositoryPort,
        client_repo: ClientRepositoryPort,
        auth_code_cache: AuthCodeCachePort,
        password_hasher: PasswordHasherPort,
        auth_code_ttl_seconds: int = 60,
    ) -> None:
        self._user_repo = user_repo
        self._client_repo = client_repo
        self._auth_code_cache = auth_code_cache
        self._password_hasher = password_hasher
        self._auth_code_ttl_seconds = auth_code_ttl_seconds

    async def execute(self, request: AuthorizeRequestDTO) -> AuthorizeResponseDTO:
        client = await self._client_repo.get_by_client_id(request.client_id)
        if not client:
            raise InvalidClientError("Unknown client_id.")

        if not client.allows_redirect_uri(request.redirect_uri):
            raise InvalidGrantError("Unregistered redirect_uri for this client.")

        requested_scopes = request.scope.split()
        if not requested_scopes or not client.validate_scopes(requested_scopes):
            raise InvalidScopeError("Requested scope is invalid or not allowed.")

        if request.code_challenge_method != "S256" or not request.code_challenge:
            raise InvalidGrantError("PKCE with S256 code_challenge_method is required.")

        # Passo 2: Autenticação do usuário junto ao Banco de Dados de Usuários
        user = await self._user_repo.get_by_email(request.user_email)
        if not user or not user.is_active:
            raise AccessDeniedError("Invalid user credentials or inactive user.")

        if not self._password_hasher.verify_secret(request.user_password, user.password_hash):
            raise AccessDeniedError("Invalid user credentials.")

        code_str = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code_str,
            client_id=client.client_id,
            user_id=user.id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            expires_at=datetime.now(UTC) + timedelta(seconds=self._auth_code_ttl_seconds),
        )

        await self._auth_code_cache.save(auth_code, ttl_seconds=self._auth_code_ttl_seconds)

        return AuthorizeResponseDTO(
            code=code_str,
            redirect_uri=request.redirect_uri,
            state=request.state,
        )


class IssueTokenUseCase:
    """Executa o Passo 3 do Fluxograma: Emissão do Access Token usando Strategy Pattern."""

    def __init__(
        self,
        client_repo: ClientRepositoryPort,
        password_hasher: PasswordHasherPort,
        strategy_factory: GrantStrategyFactory,
    ) -> None:
        self._client_repo = client_repo
        self._password_hasher = password_hasher
        self._strategy_factory = strategy_factory

    async def execute(self, request: TokenExchangeRequestDTO) -> TokenPair:
        client = await self._client_repo.get_by_client_id(request.client_id)
        if not client:
            raise InvalidClientError("Client not found.")

        if client.is_confidential:
            if not request.client_secret:
                raise InvalidClientError("Client secret is required for confidential clients.")
            if not self._password_hasher.verify_secret(
                request.client_secret, client.client_secret_hash
            ):
                raise InvalidClientError("Invalid client secret.")

        strategy = self._strategy_factory.get_strategy(request.grant_type)
        return await strategy.execute(request, client)


class IntrospectTokenUseCase:
    """Executa o Passo 5 do Fluxograma: Validação do Token via Introspecção (RFC 7662)."""

    def __init__(
        self,
        token_signer: TokenSignerPort,
        token_revocation_repo: TokenRevocationPort,
    ) -> None:
        self._token_signer = token_signer
        self._token_revocation_repo = token_revocation_repo

    async def execute(self, token: str) -> IntrospectionResult:
        """Executa a introspecção do token."""
        result = self._token_signer.decode_and_verify(token)
        if not result.active or not result.jti:
            return IntrospectionResult(active=False)

        # Verifica se o token foi revogado explicitamente (Deny-list no Redis)
        if await self._token_revocation_repo.is_access_token_revoked(result.jti):
            return IntrospectionResult(active=False)

        return result
