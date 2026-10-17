from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class ResourceServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    service_name: str = "resource-server"
    database_url: str = "postgresql+asyncpg://resource_admin:resource_secret_pwd@resource-db:5432/oauth_resources_db"


@lru_cache
def get_settings() -> ResourceServerSettings:
    return ResourceServerSettings()
