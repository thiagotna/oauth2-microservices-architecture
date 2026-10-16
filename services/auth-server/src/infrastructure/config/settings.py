from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic_settings import BaseSettings, SettingsConfigDict


def _generate_default_rsa_keypair() -> tuple[str, str]:
    """Gera um par de chaves RSA-2048 efêmero para desenvolvimento/testes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return priv_pem, pub_pem


_DEFAULT_PRIV_KEY, _DEFAULT_PUB_KEY = _generate_default_rsa_keypair()


class AuthServerSettings(BaseSettings):
    """Configurações estritamente tipadas do Servidor de Autorização."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    service_name: str = "auth-server"
    database_url: str = (
        "postgresql+asyncpg://auth_admin:auth_secret_pwd@auth-db:5432/oauth_users_db"
    )
    redis_url: str = "redis://auth-redis:6379/0"

    # Credenciais do API Gateway para autenticar a chamada do Passo 5 (/introspect)
    gateway_client_id: str = "api_gateway_internal"
    gateway_client_secret: str = "gateway_super_secret"  # noqa: S105

    # Configurações de Tokens e Criptografia Assimétrica (RS256)
    jwt_issuer: str = "http://auth-server:8001"
    access_token_ttl_seconds: int = 900  # 15 minutos
    refresh_token_ttl_days: int = 7
    auth_code_ttl_seconds: int = 60

    jwt_private_key_pem: str = _DEFAULT_PRIV_KEY
    jwt_public_key_pem: str = _DEFAULT_PUB_KEY


@lru_cache
def get_settings() -> AuthServerSettings:
    return AuthServerSettings()
