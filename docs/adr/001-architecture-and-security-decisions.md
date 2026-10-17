# ADR 001: Arquitetura de Microsserviços OAuth 2.0, Isolamento de Dados e Introspecção no Gateway

- **Status:** Aceito
- **Data:** Outubro de 2026
- **Contexto:** Engenharia de Software Orientada por IA para Sistema de Autenticação e Autorização OAuth 2.0

## 1. Contexto e Problema
Sistemas de identidade (IdP) exigem alto grau de isolamento de dados credenciais, proteção contra interceptação de códigos de autorização e revogação imediata de sessão. Além disso, ao utilizar Inteligência Artificial como copiloto de implementação, é fundamental estabelecer fronteiras arquiteturais rígidas para evitar acoplamento entre regras de protocolo (RFC 6749 / RFC 7662) e bibliotecas de infraestrutura.

## 2. Decisões Arquiteturais

### 2.1. Padrão *Database-per-Service* e Segmentação de Redes
- **Decisão:** Separar fisicamente o banco de identidade (`auth-db`) do banco de negócio (`resource-db`) em instâncias PostgreSQL distintas e sub-redes Docker isoladas (`auth_data_net` e `resource_data_net` com `internal: true`).
- **Justificativa:** Garante que uma eventual vulnerabilidade na API de negócios (`resource-server`) jamais exponha hashes de senhas ou segredos de clientes OAuth armazenados no `auth-db`.

### 2.2. API Gateway como Policy Enforcement Point (PEP) via RFC 7662
- **Decisão:** O `api-gateway` intercepta todas as chamadas externas (Passo 4) e realiza **Token Introspection (Passo 5)** junto ao `auth-server` antes de encaminhar a requisição ao `resource-server` (Passo 6).
- **Justificativa:** Embora tokens JWT `RS256` possam ser validados localmente via chave pública, a introspecção centralizada permite verificar em tempo real no Redis (`auth-redis`) se o `jti` do token foi revogado (Deny-list), garantindo invalidação instantânea de sessão.

### 2.3. Consumo Atômico de Authorization Codes (`GETDEL` no Redis) + PKCE S256
- **Decisão:** Armazenar códigos de autorização no Redis com TTL de 60 segundos e consumi-los via operação atômica `GETDEL`, exigindo validação criptográfica `S256` (RFC 7636).
- **Justificativa:** Mitiga ataques de *Authorization Code Interception* e condições de corrida (*Race Conditions*) onde um atacante tenta trocar o mesmo código simultaneamente em múltiplas conexões.

### 2.4. Clean Architecture + Hexagonal e Tipagem Estrita (`mypy --strict`)
- **Decisão:** Isolar `domain` e `application` de qualquer dependência de I/O e exigir aprovação em `mypy --strict`, `ruff` e `bandit`.
- **Justificativa:** Atua como barreira determinística contra alucinações do LLM, garantindo contratos formais (`typing.Protocol`) e 100% de testabilidade unitária.
