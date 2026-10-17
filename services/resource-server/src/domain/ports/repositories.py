from typing import Protocol

from src.domain.entities.resource_models import ProtectedResource


class ProtectedResourceRepositoryPort(Protocol):
    """Contrato para consulta e persistência no Banco de Dados de Recursos (Passo 7)."""

    async def list_by_owner(self, owner_id: str) -> list[ProtectedResource]: ...

    async def create(
        self, owner_id: str, title: str, content: str, classification: str
    ) -> ProtectedResource: ...
