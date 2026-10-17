# AI-Assisted Software Engineering — Context & Prompting Log

Este documento registra a estratégia de **Engenharia de Contexto e Direcionamento Arquitetural** utilizada para guiar o modelo de IA na construção deste sistema distribuído OAuth 2.0.

## Metodologia Aplicada: *Architecture-First & Guardrail-Driven AI*

Em vez de utilizar prompts genéricos (*"Crie um servidor OAuth em Python"*), a condução do LLM foi dividida em **7 fases determinísticas**, onde cada camada só foi gerada após validação estática (`mypy --strict`, `ruff`, `bandit`) e testes automatizados da camada anterior:

### Fase 1: Topologia e Isolamento Físico (Zero-Trust Infrastructure)
- **Diretriz do Engenheiro:** Traduzir fielmente o fluxograma arquitetural separando fisicamente o Servidor de Autorização (`auth-server` + `auth-db`) do Servidor de Recursos (`resource-server` + `resource-db`), intermediados por um `api-gateway`.
- **Restrição imposta à IA:** Configurar redes Docker isoladas (`internal: true`) para garantir que o `resource-server` e os bancos de dados sejam inacessíveis diretamente pela rede pública.

### Fase 2: Contrato de Governança (`.ai/system-instructions.md`)
- **Diretriz do Engenheiro:** Estabelecer regras imutáveis de Clean Architecture, Arquitetura Hexagonal (Ports & Adapters), SOLID e proibição de `Any` antes da geração de qualquer linha de código de negócio.

### Fase 3: Walking Skeleton & Guardrails Automatizados
- **Diretriz do Engenheiro:** Construir a casca mínima executável dos 3 microsserviços com healthchecks e pipeline de validação (`Makefile` com `lint`, `typecheck`, `security`).
- **Correção de Engenharia:** Ajuste de volumes para sincronização em tempo real e calibração de regras SAST (`S105`/`S106`) para separar constantes públicas da RFC 6749 (`Bearer`) de segredos reais.

### Fase 4: Modelagem de Domínio Pura (`src/domain/`)
- **Diretriz do Engenheiro:** Criar Entidades imutáveis (`dataclass(frozen=True, slots=True)`), Exceções padronizadas pela RFC 6749 e Contratos (`typing.Protocol`) sem dependências de frameworks externos.

### Fase 5: Casos de Uso e Design Patterns (`src/application/`)
- **Diretriz do Engenheiro:** Aplicar **Strategy Pattern** e **Factory Pattern** para suportar múltiplos fluxos OAuth 2.0 (`authorization_code` com PKCE `S256`, `client_credentials` e `refresh_token` com rotação) respeitando o *Open/Closed Principle*.
- **Validação:** Testes unitários em memória comprovando uso único (*single-use*) do Authorization Code e bloqueio de credenciais inválidas.

### Fase 6: Adaptadores de Infraestrutura e Criptografia (`src/infrastructure/`)
- **Diretriz do Engenheiro:** Implementar as *Ports* usando `SQLAlchemy 2.0` assíncrono (`asyncpg`), `Redis` com comando atômico `GETDEL` (prevenção de *Race Condition*), hash de senhas com `Argon2id` e assinatura JWT assimétrica `RS256`.

### Fase 7: API Gateway (PEP) e Validação End-to-End (Passos 1 a 8)
- **Diretriz do Engenheiro:** Implementar a **RFC 7662 (Token Introspection)** no `api-gateway` (Passo 5) autenticada via HTTP Basic Auth e propagar o contexto de segurança (`X-User-Id`, `X-OAuth-Scopes`) ao `resource-server` (Passos 6 e 7).
