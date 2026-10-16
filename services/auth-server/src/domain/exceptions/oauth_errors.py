class OAuthDomainError(Exception):
    """Classe base para erros de negócio padronizados pela RFC 6749."""

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code


class InvalidClientError(OAuthDomainError):
    def __init__(self, description: str = "Client authentication failed.") -> None:
        super().__init__(error="invalid_client", description=description, status_code=401)


class InvalidGrantError(OAuthDomainError):
    def __init__(
        self, description: str = "The provided authorization grant or refresh token is invalid."
    ) -> None:
        super().__init__(error="invalid_grant", description=description, status_code=400)


class UnauthorizedClientError(OAuthDomainError):
    def __init__(
        self, description: str = "The client is not authorized to use this grant type."
    ) -> None:
        super().__init__(error="unauthorized_client", description=description, status_code=400)


class InvalidScopeError(OAuthDomainError):
    def __init__(self, description: str = "The requested scope is invalid or unknown.") -> None:
        super().__init__(error="invalid_scope", description=description, status_code=400)


class UnsupportedGrantTypeError(OAuthDomainError):
    def __init__(self, description: str = "The authorization grant type is not supported.") -> None:
        super().__init__(error="unsupported_grant_type", description=description, status_code=400)


class AccessDeniedError(OAuthDomainError):
    def __init__(
        self, description: str = "The resource owner or server denied the request."
    ) -> None:
        super().__init__(error="access_denied", description=description, status_code=403)
