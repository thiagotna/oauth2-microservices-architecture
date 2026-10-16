from typing import Protocol
from uuid import UUID

from src.domain.entities.models import OAuthClient, User
from src.domain.entities.tokens import AuthorizationCode, RefreshTokenData


class UserRepositoryPort(Protocol):
    """Contrato de comunicação com o Banco de Dados de Usuários (Passo 2)."""

    async def get_by_email(self, email: str) -> User | None: ...

    async def get_by_id(self, user_id: UUID) -> User | None: ...


class ClientRepositoryPort(Protocol):
    """Contrato para busca de clientes OAuth registrados."""

    async def get_by_client_id(self, client_id: str) -> OAuthClient | None: ...


class AuthCodeCachePort(Protocol):
    """Contrato para armazenamento efêmero (single-use) de Authorization Codes no Redis."""

    async def save(self, auth_code: AuthorizationCode, ttl_seconds: int) -> None: ...

    async def consume(self, code: str) -> AuthorizationCode | None:
        """Busca e remove atomicamente o código para garantir uso único (RFC 6749)."""
        ...


class TokenRevocationPort(Protocol):
    """Contrato para gestão de Refresh Tokens e Deny-list de Access Tokens (Passo 5)."""

    async def save_refresh_token(self, token_data: RefreshTokenData) -> None: ...

    async def get_refresh_token(self, token_id: str) -> RefreshTokenData | None: ...

    async def revoke_refresh_token(self, token_id: str) -> None: ...

    async def revoke_access_token_jti(self, jti: str, ttl_seconds: int) -> None: ...

    async def is_access_token_revoked(self, jti: str) -> bool: ...
