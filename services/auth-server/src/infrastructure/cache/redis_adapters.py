import json
from datetime import datetime
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.tokens import AuthorizationCode, RefreshTokenData
from src.infrastructure.database.models import RefreshTokenModel


class RedisAuthCodeCacheAdapter:
    """Implementa AuthCodeCachePort usando Redis com consumo atômico (GETDEL)."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def save(self, auth_code: AuthorizationCode, ttl_seconds: int) -> None:
        key = f"oauth:auth_code:{auth_code.code}"
        payload = json.dumps(
            {
                "code": auth_code.code,
                "client_id": auth_code.client_id,
                "user_id": str(auth_code.user_id),
                "redirect_uri": auth_code.redirect_uri,
                "scope": auth_code.scope,
                "code_challenge": auth_code.code_challenge,
                "code_challenge_method": auth_code.code_challenge_method,
                "expires_at": auth_code.expires_at.isoformat(),
            }
        )
        await self._redis.setex(key, ttl_seconds, payload)

    async def consume(self, code: str) -> AuthorizationCode | None:
        key = f"oauth:auth_code:{code}"
        raw_data = await self._redis.getdel(key)
        if not raw_data:
            return None

        data = json.loads(raw_data)
        return AuthorizationCode(
            code=str(data["code"]),
            client_id=str(data["client_id"]),
            user_id=UUID(str(data["user_id"])),
            redirect_uri=str(data["redirect_uri"]),
            scope=str(data["scope"]),
            code_challenge=str(data["code_challenge"]),
            code_challenge_method=str(data["code_challenge_method"]),
            expires_at=datetime.fromisoformat(str(data["expires_at"])),
        )


class HybridTokenRevocationAdapter:
    """Implementa TokenRevocationPort usando Postgres (Refresh Tokens) e Redis (Deny-list JTI)."""

    def __init__(self, session: AsyncSession, redis_client: Redis) -> None:
        self._session = session
        self._redis = redis_client

    async def save_refresh_token(self, token_data: RefreshTokenData) -> None:
        model = RefreshTokenModel(
            token_id=token_data.token_id,
            user_id=token_data.user_id,
            client_id=token_data.client_id,
            scope=token_data.scope,
            is_revoked=token_data.is_revoked,
            expires_at=token_data.expires_at,
        )
        self._session.add(model)
        await self._session.commit()

    async def get_refresh_token(self, token_id: str) -> RefreshTokenData | None:
        stmt = select(RefreshTokenModel).where(RefreshTokenModel.token_id == token_id)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if not row:
            return None

        return RefreshTokenData(
            token_id=row.token_id,
            user_id=row.user_id,
            client_id=row.client_id,
            scope=row.scope,
            is_revoked=row.is_revoked,
            expires_at=row.expires_at,
        )

    async def revoke_refresh_token(self, token_id: str) -> None:
        stmt = (
            update(RefreshTokenModel)
            .where(RefreshTokenModel.token_id == token_id)
            .values(is_revoked=True)
        )
        await self._session.execute(stmt)
        await self._session.commit()

    async def revoke_access_token_jti(self, jti: str, ttl_seconds: int) -> None:
        await self._redis.setex(f"oauth:revoked_jti:{jti}", ttl_seconds, "1")

    async def is_access_token_revoked(self, jti: str) -> bool:
        exists = await self._redis.exists(f"oauth:revoked_jti:{jti}")
        return bool(exists > 0)
