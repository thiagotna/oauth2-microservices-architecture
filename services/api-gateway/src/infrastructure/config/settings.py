from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    service_name: str = "api-gateway"
    auth_server_introspect_url: str = "http://auth-server:8001/api/v1/oauth/introspect"
    resource_server_base_url: str = "http://resource-server:8002"
    gateway_client_id: str = "api_gateway_internal"
    gateway_client_secret: str = "gateway_super_secret"  # noqa: S105
    http_timeout_seconds: float = 5.0


@lru_cache
def get_settings() -> GatewaySettings:
    return GatewaySettings()
