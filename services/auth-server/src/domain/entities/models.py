from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class User:
    """Representa o Resource Owner (Usuário) armazenado no Banco de Dados de Usuários."""

    id: UUID
    email: str
    password_hash: str
    is_active: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class OAuthClient:
    """Representa uma aplicação cliente registrada no Servidor de Autorização."""

    id: UUID
    client_id: str
    client_secret_hash: str
    name: str
    redirect_uris: tuple[str, ...]
    allowed_scopes: tuple[str, ...]
    allowed_grant_types: tuple[str, ...]
    is_confidential: bool

    def allows_redirect_uri(self, uri: str) -> bool:
        return uri in self.redirect_uris

    def allows_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.allowed_grant_types

    def validate_scopes(self, requested_scopes: list[str]) -> bool:
        return all(scope in self.allowed_scopes for scope in requested_scopes)