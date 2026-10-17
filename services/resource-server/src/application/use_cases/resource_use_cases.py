from src.domain.entities.resource_models import ProtectedResource
from src.domain.exceptions.resource_errors import MissingIdentityContextError
from src.domain.ports.repositories import ProtectedResourceRepositoryPort


class ListProtectedResourcesUseCase:
    """Executa a consulta ao Banco de Dados de Recursos para o Passo 6 e 7."""

    def __init__(self, repo: ProtectedResourceRepositoryPort) -> None:
        self._repo = repo

    async def execute(self, owner_id: str) -> list[ProtectedResource]:
        if not owner_id.strip():
            raise MissingIdentityContextError("X-User-Id header is required.")
        return await self._repo.list_by_owner(owner_id)


class CreateProtectedResourceUseCase:
    """Cria um novo recurso protegido no Banco de Dados de Recursos (Passo 6 e 7)."""

    def __init__(self, repo: ProtectedResourceRepositoryPort) -> None:
        self._repo = repo

    async def execute(
        self, owner_id: str, title: str, content: str, classification: str = "CONFIDENTIAL"
    ) -> ProtectedResource:
        if not owner_id.strip():
            raise MissingIdentityContextError("X-User-Id header is required.")
        return await self._repo.create(
            owner_id=owner_id,
            title=title,
            content=content,
            classification=classification,
        )
