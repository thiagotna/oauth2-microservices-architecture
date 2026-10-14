.PHONY: help up down restart logs ps lint format typecheck security quality test test-e2e migrate-auth migrate-resource clean

DOCKER_COMPOSE = docker compose

help: ## Exibe todos os comandos disponíveis no projeto
	@echo "========================================================================="
	@echo "  OAuth 2.0 Microservices Architecture - AI-Assisted Engineering CLI"
	@echo "========================================================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# =========================================================================
# 1. INFRAESTRUTURA & ORQUESTRAÇÃO (Docker Compose)
# =========================================================================
up: ## Constrói e sobe toda a infraestrutura (Auth, Gateway, Resource e Bancos)
	$(DOCKER_COMPOSE) up -d --build

down: ## Para e remove os containers e redes
	$(DOCKER_COMPOSE) down

restart: down up ## Reinicia todos os microsserviços

logs: ## Exibe os logs em tempo real de todos os containers
	$(DOCKER_COMPOSE) logs -f

ps: ## Lista o status e healthcheck dos containers
	$(DOCKER_COMPOSE) ps

# =========================================================================
# 2. GUARDRAILS DE QUALIDADE & SEGURANÇA (Auditoria do código gerado por IA)
# =========================================================================
lint: ## Executa análise estática de estilo e boas práticas (Ruff)
	$(DOCKER_COMPOSE) exec auth-server ruff check src tests
	$(DOCKER_COMPOSE) exec api-gateway ruff check src tests
	$(DOCKER_COMPOSE) exec resource-server ruff check src tests

format: ## Formata o código automaticamente seguindo a PEP8 (Ruff)
	$(DOCKER_COMPOSE) exec auth-server ruff format src tests
	$(DOCKER_COMPOSE) exec api-gateway ruff format src tests
	$(DOCKER_COMPOSE) exec resource-server ruff format src tests

typecheck: ## Valida tipagem estática em modo estrito (Mypy --strict, zero 'Any')
	$(DOCKER_COMPOSE) exec auth-server mypy --strict src
	$(DOCKER_COMPOSE) exec api-gateway mypy --strict src
	$(DOCKER_COMPOSE) exec resource-server mypy --strict src

security: ## Executa scanner SAST de vulnerabilidades em código Python (Bandit)
	$(DOCKER_COMPOSE) exec auth-server bandit -r src/ -ll
	$(DOCKER_COMPOSE) exec api-gateway bandit -r src/ -ll
	$(DOCKER_COMPOSE) exec resource-server bandit -r src/ -ll

quality: lint typecheck security ## Executa todos os Guardrails de Engenharia em sequência

# =========================================================================
# 3. TESTES AUTOMATIZADOS & MIGRAÇÕES DE BANCO DE DADOS
# =========================================================================
test: ## Executa testes unitários e de integração em cada microsserviço
	$(DOCKER_COMPOSE) exec auth-server pytest -v --cov=src
	$(DOCKER_COMPOSE) exec api-gateway pytest -v --cov=src
	$(DOCKER_COMPOSE) exec resource-server pytest -v --cov=src

test-e2e: ## Executa o teste End-to-End validando os Passos 1 a 8 do fluxograma
	pytest tests-e2e/ -v

migrate-auth: ## Aplica migrações (Alembic) no Banco de Dados de Usuários (auth-db)
	$(DOCKER_COMPOSE) exec auth-server alembic upgrade head

migrate-resource: ## Aplica migrações (Alembic) no Banco de Dados de Recursos (resource-db)
	$(DOCKER_COMPOSE) exec resource-server alembic upgrade head

clean: ## Remove containers, volumes e diretórios de cache locais
	$(DOCKER_COMPOSE) down -v --remove-orphans
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +