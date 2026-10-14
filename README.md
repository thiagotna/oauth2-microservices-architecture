# 🔐 OAuth 2.0 Microservices Architecture — AI-Driven Software Engineering

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Async_I%2FO-009688?logo=fastapi&logoColor=white)
![Architecture](https://img.shields.io/badge/Architecture-Clean_%2B_Hexagonal-orange)
![Pattern](https://img.shields.io/badge/Microservices-Database_per_Service-blueviolet)
![Type Safety](https://img.shields.io/badge/Mypy-Strict_Mode-success)
![OAuth 2.0](https://img.shields.io/badge/OAuth_2.0-RFC_6749_%7C_RFC_7662_%7C_PKCE-critical)

## 🎯 Sobre o Projeto: Engenharia de Software Orientada por IA

Este repositório apresenta a implementação completa de uma infraestrutura distribuída de autenticação e autorização **OAuth 2.0**, construída sob a metodologia de **AI-Assisted Software Engineering**.

O objetivo central deste projeto não é demonstrar domínio mecânico da sintaxe Python, mas evidenciar como **fundamentos sólidos de Engenharia de Software (Clean Architecture, Arquitetura Hexagonal, SOLID, Design Patterns e Security by Design)** permitem orquestrar modelos de Inteligência Artificial (LLMs) para construir sistemas críticos, escaláveis, performáticos e seguros em qualquer stack tecnológica.

### Pilares de Governança sobre a IA neste Repositório:

1. **Engenharia de Contexto Explícita:** As regras arquiteturais e restrições impostas ao LLM estão documentadas e versionadas em [`.ai/system-instructions.md`](./.ai/system-instructions.md).
2. **Isolamento de Domínio e Contratos Fortes:** Uso estrito de _Ports & Adapters_ (`typing.Protocol`) para impedir acoplamento entre regras de negócio, frameworks web e bancos de dados.
3. **Verificação Estática Automatizada (Guardrails):** O código gerado pela IA é submetido a validação estrita de tipos (`mypy --strict`), linting (`ruff`), varredura de segurança SAST (`bandit`) e testes automatizados (`pytest`).

---

## 🏗️ Topologia de Infraestrutura e Fluxo Arquitetural

A arquitetura implementa o padrão **Database-per-Service** com segmentação de redes Docker (**Zero-Trust Network**), refletindo fielmente os 8 passos do diagrama abaixo:

![Fluxograma de Infraestrutura - Autenticação OAuth 2.0](./docs/architecture.png)

### Detalhamento do Fluxo de Comunicação (Passos 1 a 8)

| Passo | Origem $\rightarrow$ Destino                                        | Responsabilidade Arquitetural                                                                                                        | Rede Docker                         |
| :---: | :------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------- |
| **1** | **Cliente / Usuário** $\rightarrow$ **Servidor de Autorização**     | Solicitação de autorização (`/authorize`) com desafio **PKCE (`S256`)** (RFC 7636).                                                  | `public_net` (`:8001`)              |
| **2** | **Servidor de Autorização** $\leftrightarrow$ **Banco de Usuários** | Validação de credenciais (hash **Argon2id**), verificação de consentimento no `auth-db` e geração de código efêmero no `auth-redis`. | `auth_data_net` (`internal`)        |
| **3** | **Servidor de Autorização** $\rightarrow$ **Cliente / Usuário**     | Troca do código de autorização + `code_verifier` pelo **Access Token** e **Refresh Token** (`/token`).                               | `public_net` (`:8001`)              |
| **4** | **Cliente / Usuário** $\rightarrow$ **Gateway de API**              | Chamada à API de negócio enviando o header `Authorization: Bearer <Access_Token>`.                                                   | `public_net` (`:8000`)              |
| **5** | **Gateway de API** $\leftrightarrow$ **Servidor de Autorização**    | **Introspecção de Token (RFC 7662):** O Gateway valida no `/oauth/introspect` se o token está ativo, íntegro e não revogado.         | `intranet_gateway_net` (`internal`) |
| **6** | **Gateway de API** $\rightarrow$ **Servidor de Recursos**           | Proxy reverso assíncrono encaminhando a requisição autorizada com headers internos (`X-User-Id`, `X-OAuth-Scopes`).                  | `intranet_gateway_net` (`internal`) |
| **7** | **Servidor de Recursos** $\rightarrow$ **Gateway de API**           | Consulta isolada ao **Banco de Dados de Recursos** (`resource-db`) e retorno dos dados solicitados.                                  | `resource_data_net` (`internal`)    |
| **8** | **Gateway de API** $\rightarrow$ **Cliente / Usuário**              | Entrega da resposta final ao cliente.                                                                                                | `public_net` (`:8000`)              |

---

## 🧩 Design Patterns e Arquitetura Interna

Cada microsserviço em `services/` possui seu próprio ciclo de vida e segue **Clean Architecture + Hexagonal Architecture**:

- **Strategy Pattern (`GrantTypeStrategy`):** No `auth-server`, cada fluxo OAuth 2.0 (`authorization_code`, `client_credentials`, `refresh_token`) é encapsulado em uma estratégia independente, garantindo aderência ao _Open/Closed Principle (SOLID)_.
- **Factory Pattern:** Instanciação dinâmica da estratégia de concessão e construção de tokens assinados.
- **Repository Pattern (100% Async I/O):** Abstração das operações no PostgreSQL (`SQLAlchemy 2.0 + asyncpg`) e Redis (`redis.asyncio`) através de _Ports_ definidas na camada de domínio.
- **API Gateway / Reverse Proxy Pattern:** O `api-gateway` atua como barreira de segurança centralizada (PEP - _Policy Enforcement Point_), mantendo o `resource-server` inacessível à rede pública.

---

## 📂 Estrutura de Diretórios

```text
.
├── .ai/
│   ├── system-instructions.md    # Contrato de arquitetura, segurança e tipagem para a IA
│   └── prompts-log.md            # Registro da engenharia de prompts por feature
├── docs/
│   ├── adr/                      # Architecture Decision Records
│   └── architecture.png          # Fluxograma oficial da infraestrutura
├── services/
│   ├── auth-server/              # Servidor de Autorização (OAuth 2.0 / IdP) - Passos 1, 2, 3 e 5
│   │   └── src/
│   │       ├── domain/           # Entidades puras, Value Objects, Exceções e Ports (Interfaces)
│   │       ├── application/      # Casos de Uso, Strategies (Grant Types) e DTOs
│   │       ├── infrastructure/   # Adaptadores Postgres (auth-db), Redis, Argon2 e JWT
│   │       └── presentation/     # Endpoints FastAPI e Injeção de Dependência
│   ├── api-gateway/              # Gateway de API (Reverse Proxy + Introspection) - Passos 4, 5, 6 e 8
│   └── resource-server/          # Servidor de Recursos (APIs de Negócio) - Passos 6 e 7
├── tests-e2e/                    # Testes End-to-End simulando a jornada completa (Passos 1 a 8)
├── docker-compose.yml            # Topologia completa com isolamento de sub-redes (Zero-Trust)
├── Makefile                      # CLI padronizada de automação e validação de qualidade
└── README.md
```
