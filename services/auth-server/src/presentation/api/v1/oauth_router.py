from typing import Annotated

from fastapi import APIRouter, Depends, Form

from src.application.dtos.oauth_dtos import AuthorizeRequestDTO, TokenExchangeRequestDTO
from src.application.use_cases.oauth_use_cases import (
    AuthorizeUserUseCase,
    IntrospectTokenUseCase,
    IssueTokenUseCase,
)
from src.presentation.api.v1.schemas import (
    AuthorizeRequestSchema,
    AuthorizeResponseSchema,
    IntrospectionResponseSchema,
    TokenResponseSchema,
)
from src.presentation.dependencies import (
    get_authorize_use_case,
    get_introspect_use_case,
    get_issue_token_use_case,
    verify_gateway_basic_auth,
)

router = APIRouter(prefix="/api/v1/oauth", tags=["OAuth 2.0 Protocol"])


@router.post("/authorize", response_model=AuthorizeResponseSchema)
async def authorize_endpoint(
    payload: AuthorizeRequestSchema,
    use_case: Annotated[AuthorizeUserUseCase, Depends(get_authorize_use_case)],
) -> AuthorizeResponseSchema:
    """Passos 1 e 2: Solicitação de autorização, autenticação do utilizador e emissão do code."""
    result = await use_case.execute(
        AuthorizeRequestDTO(
            client_id=payload.client_id,
            redirect_uri=payload.redirect_uri,
            scope=payload.scope,
            code_challenge=payload.code_challenge,
            code_challenge_method=payload.code_challenge_method,
            user_email=str(payload.user_email),
            user_password=payload.user_password,
            state=payload.state,
        )
    )
    return AuthorizeResponseSchema(
        code=result.code,
        redirect_uri=result.redirect_uri,
        state=result.state,
    )


@router.post("/token", response_model=TokenResponseSchema)
async def token_endpoint(
    use_case: Annotated[IssueTokenUseCase, Depends(get_issue_token_use_case)],
    grant_type: Annotated[str, Form(...)],
    client_id: Annotated[str, Form(...)],
    client_secret: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
) -> TokenResponseSchema:
    """Passo 3: Emissão do Access Token (aceita application/x-www-form-urlencoded como exige a
    RFC 6749)."""
    token_pair = await use_case.execute(
        TokenExchangeRequestDTO(
            grant_type=grant_type,
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            scope=scope,
        )
    )
    return TokenResponseSchema(
        access_token=token_pair.access_token,
        token_type=token_pair.token_type,
        expires_in=token_pair.expires_in,
        refresh_token=token_pair.refresh_token,
        scope=token_pair.scope,
    )


@router.post("/introspect", response_model=IntrospectionResponseSchema)
async def introspect_endpoint(
    token: Annotated[str, Form(...)],
    _gateway_client: Annotated[str, Depends(verify_gateway_basic_auth)],
    use_case: Annotated[IntrospectTokenUseCase, Depends(get_introspect_use_case)],
) -> IntrospectionResponseSchema:
    """Passo 5: Validação do Token via Introspeção (RFC 7662) chamada pelo API Gateway."""
    result = await use_case.execute(token)
    return IntrospectionResponseSchema(
        active=result.active,
        scope=result.scope,
        client_id=result.client_id,
        sub=result.sub,
        exp=result.exp,
        iat=result.iat,
        jti=result.jti,
    )
