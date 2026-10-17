class ResourceDomainError(Exception):
    def __init__(self, error: str, description: str, status_code: int) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code


class MissingIdentityContextError(ResourceDomainError):
    def __init__(
        self, description: str = "Missing trusted identity headers from API Gateway."
    ) -> None:
        super().__init__(error="unauthorized_context", description=description, status_code=401)
