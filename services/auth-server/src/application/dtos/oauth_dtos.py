from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthorizeRequestDTO:
    """Dados de entrada para os Passos 1 e 2 (Solicitação de Autorização + Credenciais)."""

    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    user_email: str
    user_password: str
    state: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizeResponseDTO:
    """Resposta do Passo 2 contendo o Authorization Code temporário."""

    code: str
    redirect_uri: str
    state: str | None = None


@dataclass(frozen=True, slots=True)
class TokenExchangeRequestDTO:
    """Dados de entrada unificados para o Passo 3 (Emissão de Token via Strategy)."""

    grant_type: str
    client_id: str
    client_secret: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None
    scope: str | None = None