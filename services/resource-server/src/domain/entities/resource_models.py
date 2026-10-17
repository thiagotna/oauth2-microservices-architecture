from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """Representa um registro de negócio armazenado no Banco de Dados de Recursos (resource-db)."""

    id: UUID
    owner_id: str
    title: str
    content: str
    classification: str
    created_at: datetime
