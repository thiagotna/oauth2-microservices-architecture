import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from src.domain.entities.tokens import IntrospectionResult


class Argon2PasswordHasherAdapter:
    """Implementa PasswordHasherPort usando Argon2id (recomendação OWASP)."""

    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def hash_secret(self, plain_secret: str) -> str:
        return str(self._hasher.hash(plain_secret))

    def verify_secret(self, plain_secret: str, hashed_secret: str) -> bool:
        try:
            return bool(self._hasher.verify(hashed_secret, plain_secret))
        except VerifyMismatchError:
            return False


class S256PkceVerifierAdapter:
    """Implementa PkceVerifierPort segundo a RFC 7636 (SHA-256 + Base64URL sem padding)."""

    def verify_challenge(
        self, code_verifier: str, code_challenge: str, method: str = "S256"
    ) -> bool:
        if method != "S256":
            return False

        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        # Comparação em tempo constante contra ataques de timing
        return hmac.compare_digest(computed_challenge, code_challenge)


class Rs256JwtTokenSignerAdapter:
    """Implementa TokenSignerPort assinando JWTs com chave assimétrica RSA (RS256)."""

    def __init__(
        self,
        private_key_pem: str,
        public_key_pem: str,
        issuer: str,
        access_token_ttl_seconds: int = 900,
    ) -> None:
        self._private_key = private_key_pem
        self._public_key = public_key_pem
        self._issuer = issuer
        self._ttl_seconds = access_token_ttl_seconds

    def create_access_token(
        self,
        subject: str,
        client_id: str,
        scope: str,
        user_id: UUID | None = None,
    ) -> tuple[str, int, str]:
        now = datetime.now(UTC)
        exp = now + timedelta(seconds=self._ttl_seconds)
        jti = str(uuid4())

        payload: dict[str, Any] = {
            "iss": self._issuer,
            "sub": subject,
            "client_id": client_id,
            "scope": scope,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
        }
        if user_id:
            payload["user_id"] = str(user_id)

        encoded_jwt = jwt.encode(payload, self._private_key, algorithm="RS256")
        return encoded_jwt, self._ttl_seconds, jti

    def decode_and_verify(self, token: str) -> IntrospectionResult:
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                issuer=self._issuer,
            )
            return IntrospectionResult(
                active=True,
                scope=str(payload.get("scope", "")),
                client_id=str(payload.get("client_id", "")),
                sub=str(payload.get("sub", "")),
                exp=int(payload["exp"]) if "exp" in payload else None,
                iat=int(payload["iat"]) if "iat" in payload else None,
                jti=str(payload.get("jti", "")),
            )
        except jwt.PyJWTError:
            return IntrospectionResult(active=False)
