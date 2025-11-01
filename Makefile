.PHONY: help build up down logs clean test migrate shell

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build all Docker images
	docker compose build

up: ## Start all services
	docker compose up -d

up-build: ## Build and start all services
	docker compose up -d --build

down: ## Stop all services
	docker compose down

down-volumes: ## Stop all services and remove volumes
	docker compose down -v

logs: ## View logs from all services
	docker compose logs -f

logs-api: ## View API logs
	docker compose logs -f api

logs-worker: ## View worker logs
	docker compose logs -f worker

logs-web: ## View web logs
	docker compose logs -f web

ps: ## List running services
	docker compose ps

restart: ## Restart all services
	docker compose restart

restart-api: ## Restart API service
	docker compose restart api

restart-worker: ## Restart worker service
	docker compose restart worker

migrate: ## Run database migrations
	docker compose exec api alembic upgrade head

migrate-create: ## Create a new migration (use: make migrate-create MESSAGE="description")
	docker compose exec api alembic revision --autogenerate -m "$(MESSAGE)"

shell-api: ## Open shell in API container
	docker compose exec api /bin/bash

shell-worker: ## Open shell in worker container
	docker compose exec worker /bin/bash

shell-web: ## Open shell in web container
	docker compose exec web /bin/sh

shell-db: ## Open PostgreSQL shell
	docker compose exec db psql -U admin -d iam_copilot

shell-redis: ## Open Redis CLI
	docker compose exec redis redis-cli

test: ## Run tests
	docker compose exec api pytest -v

test-coverage: ## Run tests with coverage
	docker compose exec api pytest --cov=app --cov-report=html

clean: ## Remove all containers, volumes, and images
	docker compose down -v --rmi all
	rm -rf api/__pycache__ worker/__pycache__
	rm -rf web/node_modules web/dist

health: ## Check health of all services
	@echo "API Health:"
	@curl -s http://localhost:8000/health | jq || echo "API not responding"
	@echo "\nDatabase:"
	@docker compose exec db pg_isready -U admin || echo "Database not ready"
	@echo "\nRedis:"
	@docker compose exec redis redis-cli ping || echo "Redis not responding"

install-dev: ## Install development dependencies
	cd api && pip install -r requirements.txt
	cd web && npm install

setup: ## Initial setup (copy .env, build, migrate)
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file. Please edit it with your AWS credentials."; \
	fi
	$(MAKE) up-build
	sleep 10
	$(MAKE) migrate
	@echo "\nSetup complete! Visit http://localhost:3000"

.DEFAULT_GOAL := help
