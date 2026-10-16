from typing import Protocol
from uuid import UUID

from src.domain.entities.tokens import IntrospectionResult


class PasswordHasherPort(Protocol):
    """Contrato para hashing e verificação de senhas/secrets (Argon2id)."""

    def hash_secret(self, plain_secret: str) -> str: ...

    def verify_secret(self, plain_secret: str, hashed_secret: str) -> bool: ...


class PkceVerifierPort(Protocol):
    """Contrato para validação de Proof Key for Code Exchange (RFC 7636)."""

    def verify_challenge(
        self, code_verifier: str, code_challenge: str, method: str = "S256"
    ) -> bool: ...


class TokenSignerPort(Protocol):
    """Contrato para emissão e decodificação criptográfica de Access Tokens (JWT)."""

    def create_access_token(
        self,
        subject: str,
        client_id: str,
        scope: str,
        user_id: UUID | None = None,
    ) -> tuple[str, int, str]:
        """Retorna (jwt_encoded, expires_in_seconds, jti)."""
        ...

    def decode_and_verify(self, token: str) -> IntrospectionResult:
        """Verifica assinatura e expiração do token para o Passo 5 (Introspecção)."""
        ...
