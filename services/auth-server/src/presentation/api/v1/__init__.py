from pydantic import BaseModel, EmailStr, Field


class AuthorizeRequestSchema(BaseModel):
    """Payload enviado pelo Cliente/Utilizador nos Passos 1 e 2."""

    client_id: str = Field(..., min_length=3)
    redirect_uri: str = Field(..., min_length=5)
    scope: str = Field(..., min_length=3)
    code_challenge: str = Field(..., min_length=43, max_length=128)
    code_challenge_method: str = Field(default="S256")
    user_email: EmailStr
    user_password: str = Field(..., min_length=6)
    state: str | None = None


class AuthorizeResponseSchema(BaseModel):
    """Resposta do Passo 2 contendo o código de autorização temporário."""

    code: str
    redirect_uri: str
    state: str | None = None


class TokenResponseSchema(BaseModel):
    """Resposta oficial do Passo 3 (RFC 6749 Section 5.1)."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    scope: str


class IntrospectionResponseSchema(BaseModel):
    """Resposta oficial do Passo 5: Introspeção de Token (RFC 7662)."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
