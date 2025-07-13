.PHONY: help dev build up down logs shell clean test lint format deploy

# Default target
.DEFAULT_GOAL := help

# Variables
DOCKER_COMPOSE = docker-compose
DOCKER = docker
API_CONTAINER = identity-api
DB_CONTAINER = identity-db
PYTHON = python
PIP = pip
PYTEST = pytest
FLAKE8 = flake8
RUFF = ruff
BLACK = black
MYPY = mypy
ALEMBIC = alembic

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

# Help command
help: ## Show this help message
	@echo "Identity Module - Available Commands:"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\033[36m%-20s\033[0m %s\n", "Command", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "\033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Development Commands
dev: ## Start development environment
	@echo "$(GREEN)Starting development environment...$(NC)"
	$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)Development environment is ready!$(NC)"
	@echo "API: http://localhost:8000"
	@echo "API Docs: http://localhost:8000/docs"
	@echo "RabbitMQ: http://localhost:15672"

build: ## Build Docker images
	@echo "$(GREEN)Building Docker images...$(NC)"
	$(DOCKER_COMPOSE) build --no-cache

rebuild: ## Rebuild and restart services
	@echo "$(GREEN)Rebuilding services...$(NC)"
	$(DOCKER_COMPOSE) down
	$(DOCKER_COMPOSE) build --no-cache
	$(DOCKER_COMPOSE) up -d

up: ## Start all services
	@echo "$(GREEN)Starting all services...$(NC)"
	$(DOCKER_COMPOSE) up -d

down: ## Stop all services
	@echo "$(YELLOW)Stopping all services...$(NC)"
	$(DOCKER_COMPOSE) down

restart: ## Restart all services
	@echo "$(YELLOW)Restarting all services...$(NC)"
	$(DOCKER_COMPOSE) restart

logs: ## View logs from all services
	$(DOCKER_COMPOSE) logs -f

logs-api: ## View API logs only
	$(DOCKER_COMPOSE) logs -f api

shell: ## Enter API container shell
	@echo "$(GREEN)Entering API container shell...$(NC)"
	$(DOCKER) exec -it $(API_CONTAINER) /bin/bash

shell-db: ## Enter database shell
	@echo "$(GREEN)Entering database shell...$(NC)"
	$(DOCKER) exec -it $(DB_CONTAINER) psql -U identity -d identity_db

# Database Commands
db-migrate: ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(ALEMBIC) upgrade head

db-rollback: ## Rollback last migration
	@echo "$(YELLOW)Rolling back last migration...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(ALEMBIC) downgrade -1

db-reset: ## Reset database (WARNING: Destroys all data)
	@echo "$(RED)WARNING: This will destroy all data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(DOCKER) exec $(API_CONTAINER) $(ALEMBIC) downgrade base; \
		$(DOCKER) exec $(API_CONTAINER) $(ALEMBIC) upgrade head; \
		echo "$(GREEN)Database reset complete!$(NC)"; \
	fi

db-seed: ## Seed database with test data
	@echo "$(GREEN)Seeding database...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) python scripts/seed.py

db-backup: ## Backup database
	@echo "$(GREEN)Backing up database...$(NC)"
	@mkdir -p backups
	$(DOCKER) exec $(DB_CONTAINER) pg_dump -U identity identity_db > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "$(GREEN)Backup complete!$(NC)"

# Testing Commands
test: ## Run all tests
	@echo "$(GREEN)Running tests...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(PYTEST) tests/ -v

test-cov: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(PYTEST) tests/ --cov=src --cov-report=term-missing --cov-report=html

test-watch: ## Run tests in watch mode
	@echo "$(GREEN)Running tests in watch mode...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(PYTEST) tests/ -v --watch

test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(PYTEST) tests/unit/ -v

test-integration: ## Run integration tests only
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(PYTEST) tests/integration/ -v

# Code Quality Commands
lint: ## Run all linters
	@echo "$(GREEN)Running linters...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(FLAKE8) src tests --max-line-length=100
	$(DOCKER) exec $(API_CONTAINER) $(RUFF) check src tests

format: ## Format code with black
	@echo "$(GREEN)Formatting code...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(BLACK) src tests

format-check: ## Check code formatting
	@echo "$(GREEN)Checking code format...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(BLACK) --check src tests

type-check: ## Run type checking with mypy
	@echo "$(GREEN)Running type checks...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) $(MYPY) src --ignore-missing-imports

quality: lint format-check type-check ## Run all code quality checks

# Local Development (without Docker)
local-install: ## Install dependencies locally
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt

local-dev: ## Run development server locally
	@echo "$(GREEN)Starting local development server...$(NC)"
	$(PYTHON) -m uvicorn src.presentation.app:app --reload --host 0.0.0.0 --port 8000

# Deployment Commands
deploy-dev: ## Deploy to development environment
	@echo "$(GREEN)Deploying to development...$(NC)"
	./scripts/deploy.sh dev

deploy-staging: ## Deploy to staging environment
	@echo "$(GREEN)Deploying to staging...$(NC)"
	./scripts/deploy.sh staging

deploy-prod: ## Deploy to production environment
	@echo "$(RED)Deploying to production...$(NC)"
	@read -p "Are you sure you want to deploy to production? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		./scripts/deploy.sh prod; \
	fi

# Utility Commands
clean: ## Clean up generated files and caches
	@echo "$(YELLOW)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete

clean-docker: ## Clean Docker resources
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	$(DOCKER_COMPOSE) down -v
	$(DOCKER) system prune -f

status: ## Show status of all services
	@echo "$(GREEN)Service Status:$(NC)"
	$(DOCKER_COMPOSE) ps

env-example: ## Copy .env.example to .env
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN).env file created from .env.example$(NC)"; \
	else \
		echo "$(YELLOW).env file already exists$(NC)"; \
	fi

# API Documentation
docs: ## Generate API documentation
	@echo "$(GREEN)Generating API documentation...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) python scripts/generate_docs.py

# Performance Commands
profile: ## Profile API performance
	@echo "$(GREEN)Running performance profiling...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) python scripts/profile.py

benchmark: ## Run API benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) python scripts/benchmark.py

# Security Commands
security-scan: ## Run security scan
	@echo "$(GREEN)Running security scan...$(NC)"
	$(DOCKER) exec $(API_CONTAINER) bandit -r src/
	$(DOCKER) exec $(API_CONTAINER) safety check

# Git Hooks
install-hooks: ## Install git hooks
	@echo "$(GREEN)Installing git hooks...$(NC)"
	pre-commit install

# Combined Commands
setup: env-example build db-migrate ## Initial project setup
	@echo "$(GREEN)Setup complete!$(NC)"

check: quality test ## Run all checks (lint, format, type, test)
	@echo "$(GREEN)All checks passed!$(NC)"

all: clean build up db-migrate ## Clean, build, and start everything
	@echo "$(GREEN)Everything is up and running!$(NC)"

# Monitor Commands
monitor: ## Monitor all services with htop
	@echo "$(GREEN)Starting monitoring...$(NC)"
	$(DOCKER) exec -it $(API_CONTAINER) htop

monitor-db: ## Monitor database connections
	@echo "$(GREEN)Monitoring database connections...$(NC)"
	watch -n 1 "$(DOCKER) exec $(DB_CONTAINER) psql -U identity -d identity_db -c 'SELECT pid, usename, application_name, client_addr, state FROM pg_stat_activity;'"

# Version Commands
version: ## Show version information
	@echo "Identity Module Version Information:"
	@echo "API Version: $$(grep version setup.py | head -1 | cut -d'"' -f2)"
	@echo "Python: $$($(DOCKER) exec $(API_CONTAINER) python --version 2>&1)"
	@echo "Docker: $$($(DOCKER) --version)"
	@echo "Docker Compose: $$($(DOCKER_COMPOSE) --version)"