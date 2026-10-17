from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.domain.exceptions.gateway_errors import GatewayError
from src.presentation.api.gateway_router import router as gateway_router


class HealthResponse(BaseModel):
    status: str
    service: str


app = FastAPI(
    title="OAuth 2.0 API Gateway",
    version="0.1.0",
)


@app.exception_handler(GatewayError)
async def gateway_error_handler(_request: Request, exc: GatewayError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.description},
        headers={"WWW-Authenticate": f'Bearer error="{exc.error}"'},
    )


app.include_router(gateway_router)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", service="api-gateway")
