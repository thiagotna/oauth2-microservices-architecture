# System Instructions & Architectural Guardrails (AI-Assisted Engineering)

## 1. Contexto e Objetivo do Projeto

Este repositório implementa uma arquitetura de microsserviços para autenticação e autorização **OAuth 2.0 (RFC 6749)** e **Token Introspection (RFC 7662)**.
O projeto é conduzido sob a metodologia de **AI-Driven Software Engineering**, onde as decisões de arquitetura, topologia de infraestrutura, contratos de domínio e requisitos de segurança são estritamente definidos pelo Engenheiro de Software e executados pelo modelo de IA sob regras rígidas de validação estática.

---

## 2. Topologia de Infraestrutura e Fluxo Arquitetural (Passos 1 a 8)

Todo o código gerado deve respeitar o isolamento físico dos serviços definidos no fluxograma arquitetural:

1. **`auth-server` (Servidor de Autorização / IdP):**
   - Responsável pelos **Passos 1, 2, 3 e 5** do fluxograma.
   - Único serviço com permissão de rede para acessar o `auth-db` (PostgreSQL) e `auth-redis` (Redis).
2. **`api-gateway` (Gateway de API):**
   - Ponto único de entrada para consumo de recursos (**Passos 4 e 8**).
   - Intercepta requisições com `Bearer Token`, executa a **Introspecção de Token (Passo 5)** junto ao `auth-server` e, se ativo, encaminha a requisição (**Passo 6**) ao `resource-server` injetando headers de contexto (`X-User-Id`, `X-Client-Id`, `X-OAuth-Scopes`).
3. **`resource-server` (Servidor de Recursos / APIs):**
   - Responsável pelos **Passos 6 e 7**.
   - Isolado em rede interna (inacessível diretamente pelo cliente externo).
   - Único serviço com acesso ao `resource-db` (PostgreSQL).

---

## 3. Regras de Arquitetura de Software (Clean Architecture + Hexagonal)

Cada serviço em `services/` deve seguir estritamente a separação em 4 camadas, respeitando a **Regra da Dependência** (dependências apontam sempre para o centro/domínio):

- **`src/domain/` (Núcleo Isolado):**
  - Contém `entities/`, `value_objects/`, `exceptions/` e `ports/` (Interfaces abstratas usando `typing.Protocol` ou `abc.ABC`).
  - **PROIBIDO:** Importar FastAPI, SQLAlchemy, Redis, Pydantic HTTP models ou qualquer biblioteca de I/O nesta camada.
- **`src/application/` (Casos de Uso):**
  - Contém `use_cases/`, `dtos/` e `strategies/`.
  - Orquestra o domínio através das `ports`. Não conhece detalhes de banco de dados ou protocolo HTTP.
- **`src/infrastructure/` (Adaptadores Secundários / Driven):**
  - Implementa as `ports` do domínio (`PostgresUserRepository`, `RedisAuthCodeStore`, `Argon2PasswordHasher`, `JwtTokenService`).
- **`src/presentation/` (Adaptadores Primários / Driving):**
  - Rotas FastAPI, Schemas HTTP, Middlewares e Container de Injeção de Dependência (`dependencies.py`).

---

## 4. Design Patterns Obrigatórios

1. **Strategy Pattern:** Cada `grant_type` do OAuth 2.0 (`authorization_code`, `client_credentials`, `refresh_token`) deve ser uma classe isolada que implementa a interface `GrantTypeStrategy`.
2. **Repository Pattern:** Toda persistência deve ser abstraída por repositórios assíncronos baseados nas interfaces do domínio.
3. **Factory Pattern:** Seleção dinâmica da estratégia de `grant_type` e construção de tokens.
4. **Dependency Injection:** Nenhum caso de uso deve instanciar adaptadores de infraestrutura diretamente; tudo deve ser injetado via construtor.

---

## 5. Padrões de Código Python, Tipagem e Qualidade

- **Versão:** Python 3.12+.
- **100% Async I/O:** Todas as operações de banco (`asyncpg`), cache (`redis.asyncio`) e chamadas HTTP entre serviços (`httpx.AsyncClient`) devem ser assíncronas (`async/await`).
- **Tipagem Estrita (Type Safety):**
  - Todo código deve passar no `mypy --strict` sem erros.
  - Proibido o uso de `Any`. Use `TypedDict`, `dataclass(frozen=True)`, `Protocol` ou `Pydantic BaseModel`.
- **Tratamento de Erros:**
  - Proibido capturar exceções genéricas (`except Exception:`) sem relançar ou traduzir para uma exceção de domínio.
  - Respostas de erro OAuth 2.0 devem seguir estritamente o formato padrão da RFC 6749 (`{"error": "invalid_grant", "error_description": "..."}`).

---

## 6. Diretrizes de Segurança (Security by Design)

- **Senhas:** Hash exclusivamente com **Argon2id** (`argon2-cffi`).
- **PKCE (RFC 7636):** Obrigatório no fluxo `authorization_code` (`code_challenge` e `code_verifier` com método `S256`).
- **Tokens:**
  - _Authorization Codes_ devem ter TTL máximo de 60 segundos no Redis e uso único (single-use).
  - Assinatura de JWT com chaves assimétricas **RS256** ou suporte imediato a revogação via endpoint `/oauth/introspect` consultando estado no Redis/Postgres.
- **Segredos:** Nenhuma chave, senha ou credencial pode ser _hardcoded_. Tudo deve vir de variáveis de ambiente validadas com `pydantic-settings`.
