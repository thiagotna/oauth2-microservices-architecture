from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class TokenContext:
    """Resultado validado no Passo 5 (Introspecção de Token junto ao Auth Server)."""

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None

    def has_scope(self, required_scope: str) -> bool:
        if not self.scope:
            return False
        return required_scope in self.scope.split()


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    """Representa a resposta retornada pelo Servidor de Recursos."""

    status_code: int
    body: Any
    headers: dict[str, str]
