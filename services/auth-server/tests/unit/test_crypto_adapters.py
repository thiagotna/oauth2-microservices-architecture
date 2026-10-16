import base64
import hashlib
from uuid import uuid4

from src.infrastructure.config.settings import get_settings
from src.infrastructure.security.crypto_adapters import (
    Argon2PasswordHasherAdapter,
    Rs256JwtTokenSignerAdapter,
    S256PkceVerifierAdapter,
)


def test_argon2_password_hasher_roundtrip() -> None:
    hasher = Argon2PasswordHasherAdapter()
    hashed = hasher.hash_secret("MySuperStrongSecret!2026")
    assert hashed.startswith("$argon2id$")
    assert hasher.verify_secret("MySuperStrongSecret!2026", hashed) is True
    assert hasher.verify_secret("WrongSecret", hashed) is False


def test_s256_pkce_verifier_rfc7636() -> None:
    verifier_adapter = S256PkceVerifierAdapter()
    raw_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    digest = hashlib.sha256(raw_verifier.encode("ascii")).digest()
    valid_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    assert verifier_adapter.verify_challenge(raw_verifier, valid_challenge, "S256") is True
    assert verifier_adapter.verify_challenge("wrong_verifier", valid_challenge, "S256") is False


def test_rs256_jwt_signer_and_introspection_decode() -> None:
    settings = get_settings()
    signer = Rs256JwtTokenSignerAdapter(
        private_key_pem=settings.jwt_private_key_pem,
        public_key_pem=settings.jwt_public_key_pem,
        issuer=settings.jwt_issuer,
        access_token_ttl_seconds=900,
    )

    uid = uuid4()
    token, expires_in, jti = signer.create_access_token(
        subject=str(uid),
        client_id="client_app_01",
        scope="read:resources write:resources",
        user_id=uid,
    )

    assert expires_in == 900
    assert jti != ""

    introspection = signer.decode_and_verify(token)
    assert introspection.active is True
    assert introspection.sub == str(uid)
    assert introspection.client_id == "client_app_01"
    assert introspection.jti == jti

    # Token adulterado deve retornar active=False na introspecção (Passo 5)
    tampered_result = signer.decode_and_verify(token + "tampered")
    assert tampered_result.active is False
