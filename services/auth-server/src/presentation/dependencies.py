import secrets
from collections.abc import AsyncGenerator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.strategies.grant_strategies import (
    AuthorizationCodeGrantStrategy,
    ClientCredentialsGrantStrategy,
    GrantStrategyFactory,
    GrantTypeStrategy,
    RefreshTokenGrantStrategy,
)
from src.application.use_cases.oauth_use_cases import (
    AuthorizeUserUseCase,
    IntrospectTokenUseCase,
    IssueTokenUseCase,
)
from src.domain.exceptions.oauth_errors import InvalidClientError
from src.infrastructure.cache.redis_adapters import (
    HybridTokenRevocationAdapter,
    RedisAuthCodeCacheAdapter,
)
from src.infrastructure.config.settings import AuthServerSettings, get_settings
from src.infrastructure.database.models import create_session_factory
from src.infrastructure.database.repositories import (
    PostgresClientRepository,
    PostgresUserRepository,
)
from src.infrastructure.security.crypto_adapters import (
    Argon2PasswordHasherAdapter,
    Rs256JwtTokenSignerAdapter,
    S256PkceVerifierAdapter,
)

security_basic = HTTPBasic()

_settings = get_settings()
_session_factory = create_session_factory(_settings.database_url)
_redis_client = Redis.from_url(_settings.redis_url, decode_responses=True)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with _session_factory() as session:
        yield session


def get_redis_client() -> Redis:
    return _redis_client


@lru_cache
def get_password_hasher() -> Argon2PasswordHasherAdapter:
    return Argon2PasswordHasherAdapter()


@lru_cache
def get_pkce_verifier() -> S256PkceVerifierAdapter:
    return S256PkceVerifierAdapter()


@lru_cache
def get_token_signer() -> Rs256JwtTokenSignerAdapter:
    settings = get_settings()
    return Rs256JwtTokenSignerAdapter(
        private_key_pem=settings.jwt_private_key_pem,
        public_key_pem=settings.jwt_public_key_pem,
        issuer=settings.jwt_issuer,
        access_token_ttl_seconds=settings.access_token_ttl_seconds,
    )


def get_authorize_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[Redis, Depends(get_redis_client)],
    hasher: Annotated[Argon2PasswordHasherAdapter, Depends(get_password_hasher)],
    settings: Annotated[AuthServerSettings, Depends(get_settings)],
) -> AuthorizeUserUseCase:
    return AuthorizeUserUseCase(
        user_repo=PostgresUserRepository(session),
        client_repo=PostgresClientRepository(session),
        auth_code_cache=RedisAuthCodeCacheAdapter(redis),
        password_hasher=hasher,
        auth_code_ttl_seconds=settings.auth_code_ttl_seconds,
    )


def get_issue_token_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[Redis, Depends(get_redis_client)],
    hasher: Annotated[Argon2PasswordHasherAdapter, Depends(get_password_hasher)],
    pkce: Annotated[S256PkceVerifierAdapter, Depends(get_pkce_verifier)],
    signer: Annotated[Rs256JwtTokenSignerAdapter, Depends(get_token_signer)],
    settings: Annotated[AuthServerSettings, Depends(get_settings)],
) -> IssueTokenUseCase:
    auth_code_cache = RedisAuthCodeCacheAdapter(redis)
    revocation_repo = HybridTokenRevocationAdapter(session, redis)

    strategies: dict[str, GrantTypeStrategy] = {
        "authorization_code": AuthorizationCodeGrantStrategy(
            auth_code_cache=auth_code_cache,
            token_revocation_repo=revocation_repo,
            pkce_verifier=pkce,
            token_signer=signer,
            refresh_token_ttl_days=settings.refresh_token_ttl_days,
        ),
        "client_credentials": ClientCredentialsGrantStrategy(token_signer=signer),
        "refresh_token": RefreshTokenGrantStrategy(
            token_revocation_repo=revocation_repo,
            token_signer=signer,
            refresh_token_ttl_days=settings.refresh_token_ttl_days,
        ),
    }

    return IssueTokenUseCase(
        client_repo=PostgresClientRepository(session),
        password_hasher=hasher,
        strategy_factory=GrantStrategyFactory(strategies),
    )


def get_introspect_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[Redis, Depends(get_redis_client)],
    signer: Annotated[Rs256JwtTokenSignerAdapter, Depends(get_token_signer)],
) -> IntrospectTokenUseCase:
    return IntrospectTokenUseCase(
        token_signer=signer,
        token_revocation_repo=HybridTokenRevocationAdapter(session, redis),
    )


def verify_gateway_basic_auth(
    credentials: Annotated[HTTPBasicCredentials, Depends(security_basic)],
    settings: Annotated[AuthServerSettings, Depends(get_settings)],
) -> str:
    """Autentica o API Gateway na chamada do Passo 5 (/introspect) em tempo constante."""
    is_id_valid = secrets.compare_digest(credentials.username, settings.gateway_client_id)
    is_secret_valid = secrets.compare_digest(credentials.password, settings.gateway_client_secret)
    if not (is_id_valid and is_secret_valid):
        raise InvalidClientError("Invalid API Gateway credentials for token introspection.")
    return credentials.username
