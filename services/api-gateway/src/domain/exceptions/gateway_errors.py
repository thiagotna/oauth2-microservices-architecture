class GatewayError(Exception):
    def __init__(self, error: str, description: str, status_code: int) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code


class MissingOrInvalidTokenError(GatewayError):
    def __init__(self, description: str = "Bearer token is missing, expired, or invalid.") -> None:
        super().__init__(error="invalid_token", description=description, status_code=401)


class InsufficientScopeError(GatewayError):
    def __init__(
        self, description: str = "The request requires higher privileges than provided."
    ) -> None:
        super().__init__(error="insufficient_scope", description=description, status_code=403)


class UpstreamUnavailableError(GatewayError):
    def __init__(self, description: str = "Upstream service is temporarily unavailable.") -> None:
        super().__init__(error="bad_gateway", description=description, status_code=502)
