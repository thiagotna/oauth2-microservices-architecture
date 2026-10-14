import secrets
from datetime import UTC, datetime, timedelta
from typing import Protocol

from src.application.dtos.oauth_dtos import TokenExchangeRequestDTO
from src.domain.entities.models import OAuthClient
from src.domain.entities.tokens import RefreshTokenData, TokenPair
from src.domain.exceptions.oauth_errors import (
    InvalidGrantError,
    InvalidScopeError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from src.domain.ports.repositories import AuthCodeCachePort, TokenRevocationPort
from src.domain.ports.security import PkceVerifierPort, TokenSignerPort


class GrantTypeStrategy(Protocol):
    """Interface Strategy para processamento de diferentes Grant Types do OAuth 2.0."""

    async def execute(
        self, request: TokenExchangeRequestDTO, client: OAuthClient
    ) -> TokenPair: ...


class AuthorizationCodeGrantStrategy:
    """Estratégia para o fluxo Authorization Code + PKCE (RFC 6749 & RFC 7636)."""

    def __init__(
        self,
        auth_code_cache: AuthCodeCachePort,
        token_revocation_repo: TokenRevocationPort,
        pkce_verifier: PkceVerifierPort,
        token_signer: TokenSignerPort,
        refresh_token_ttl_days: int = 7,
    ) -> None:
        self._auth_code_cache = auth_code_cache
        self._token_revocation_repo = token_revocation_repo
        self._pkce_verifier = pkce_verifier
        self._token_signer = token_signer
        self._refresh_token_ttl_days = refresh_token_ttl_days

    async def execute(
        self, request: TokenExchangeRequestDTO, client: OAuthClient
    ) -> TokenPair:
        if not client.allows_grant_type("authorization_code"):
            raise UnauthorizedClientError("Client is not authorized for authorization_code.")

        if not request.code or not request.code_verifier or not request.redirect_uri:
            raise InvalidGrantError("Missing code, redirect_uri, or PKCE code_verifier.")

        # Consumo atômico (Single-Use): se alguém tentar reusar o código, já não existe mais
        auth_code = await self._auth_code_cache.consume(request.code)
        if not auth_code or auth_code.is_expired():
            raise InvalidGrantError("Authorization code is invalid or expired.")

        if auth_code.client_id != client.client_id:
            raise InvalidGrantError("Authorization code was not issued to this client.")

        if auth_code.redirect_uri != request.redirect_uri:
            raise InvalidGrantError("Redirect URI mismatch.")

        # Validação criptográfica obrigatória do PKCE
        is_pkce_valid = self._pkce_verifier.verify_challenge(
            code_verifier=request.code_verifier,
            code_challenge=auth_code.code_challenge,
            method=auth_code.code_challenge_method,
        )
        if not is_pkce_valid:
            raise InvalidGrantError("PKCE verification failed.")

        access_token, expires_in, _ = self._token_signer.create_access_token(
            subject=str(auth_code.user_id),
            client_id=client.client_id,
            scope=auth_code.scope,
            user_id=auth_code.user_id,
        )

        refresh_token_id = secrets.token_urlsafe(48)
        refresh_data = RefreshTokenData(
            token_id=refresh_token_id,
            user_id=auth_code.user_id,
            client_id=client.client_id,
            scope=auth_code.scope,
            is_revoked=False,
            expires_at=datetime.now(UTC) + timedelta(days=self._refresh_token_ttl_days),
        )
        await self._token_revocation_repo.save_refresh_token(refresh_data)

        return TokenPair(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token_id,
            scope=auth_code.scope,
        )


class ClientCredentialsGrantStrategy:
    """Estratégia para comunicação Machine-to-Machine (Client Credentials)."""

    def __init__(self, token_signer: TokenSignerPort) -> None:
        self._token_signer = token_signer

    async def execute(
        self, request: TokenExchangeRequestDTO, client: OAuthClient
    ) -> TokenPair:
        if not client.allows_grant_type("client_credentials"):
            raise UnauthorizedClientError("Client is not authorized for client_credentials.")

        requested_scope = request.scope or " ".join(client.allowed_scopes)
        scope_list = requested_scope.split()
        if not client.validate_scopes(scope_list):
            raise InvalidScopeError("Requested scope exceeds client privileges.")

        access_token, expires_in, _ = self._token_signer.create_access_token(
            subject=client.client_id,
            client_id=client.client_id,
            scope=requested_scope,
            user_id=None,
        )

        return TokenPair(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=None,
            scope=requested_scope,
        )


class RefreshTokenGrantStrategy:
    """Estratégia para renovação com Refresh Token Rotation."""

    def __init__(
        self,
        token_revocation_repo: TokenRevocationPort,
        token_signer: TokenSignerPort,
        refresh_token_ttl_days: int = 7,
    ) -> None:
        self._token_revocation_repo = token_revocation_repo
        self._token_signer = token_signer
        self._refresh_token_ttl_days = refresh_token_ttl_days

    async def execute(
        self, request: TokenExchangeRequestDTO, client: OAuthClient
    ) -> TokenPair:
        if not client.allows_grant_type("refresh_token"):
            raise UnauthorizedClientError("Client is not authorized for refresh_token.")

        if not request.refresh_token:
            raise InvalidGrantError("Missing refresh_token.")

        stored_token = await self._token_revocation_repo.get_refresh_token(request.refresh_token)
        if not stored_token or not stored_token.is_valid():
            raise InvalidGrantError("Refresh token is invalid, expired, or revoked.")

        if stored_token.client_id != client.client_id:
            raise InvalidGrantError("Refresh token does not belong to this client.")

        # Rotação de segurança: revoga o Refresh Token usado imediatamente
        await self._token_revocation_repo.revoke_refresh_token(stored_token.token_id)

        subject = str(stored_token.user_id) if stored_token.user_id else client.client_id
        access_token, expires_in, _ = self._token_signer.create_access_token(
            subject=subject,
            client_id=client.client_id,
            scope=stored_token.scope,
            user_id=stored_token.user_id,
        )

        new_refresh_id = secrets.token_urlsafe(48)
        new_refresh_data = RefreshTokenData(
            token_id=new_refresh_id,
            user_id=stored_token.user_id,
            client_id=client.client_id,
            scope=stored_token.scope,
            is_revoked=False,
            expires_at=datetime.now(UTC) + timedelta(days=self._refresh_token_ttl_days),
        )
        await self._token_revocation_repo.save_refresh_token(new_refresh_data)

        return TokenPair(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_refresh_id,
            scope=stored_token.scope,
        )


class GrantStrategyFactory:
    """Factory Pattern para resolver a estratégia de Grant Type sem acoplamento."""

    def __init__(self, strategies: dict[str, GrantTypeStrategy]) -> None:
        self._strategies = strategies

    def get_strategy(self, grant_type: str) -> GrantTypeStrategy:
        strategy = self._strategies.get(grant_type)
        if not strategy:
            raise UnsupportedGrantTypeError(f"Grant type '{grant_type}' is not supported.")
        return strategy