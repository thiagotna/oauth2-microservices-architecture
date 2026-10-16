from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

BEARER_TOKEN_TYPE: Final[str] = "Bearer"  # noqa: S105 # nosec B105


@dataclass(frozen=True, slots=True)
class AuthorizationCode:
    """Código temporário emitido no Passo 1/2 (com suporte obrigatório a PKCE S256)."""

    code: str
    client_id: str
    user_id: UUID
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


@dataclass(frozen=True, slots=True)
class TokenPair:
    """Resposta emitida no Passo 3 (Envio do Token de Acesso)."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None
    scope: str


@dataclass(frozen=True, slots=True)
class RefreshTokenData:
    """Representa um Refresh Token persistido para rotação segura."""

    token_id: str
    user_id: UUID | None
    client_id: str
    scope: str
    is_revoked: bool
    expires_at: datetime

    def is_valid(self) -> bool:
        return not self.is_revoked and datetime.now(UTC) < self.expires_at


@dataclass(frozen=True, slots=True)
class IntrospectionResult:
    """Contrato de resposta do Passo 5: Validação do Token via Introspecção (RFC 7662)."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
