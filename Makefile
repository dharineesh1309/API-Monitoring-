.PHONY: up up-aws down restart build logs health status traffic clean ps test help

# Default target
.DEFAULT_GOAL := help

## help: Show this help message
help:
	@echo "CentralWatch — available make targets:"
	@echo ""
	@echo "  up          Start the stack in localstack mode (builds images)"
	@echo "  up-aws      Start the stack in AWS mode"
	@echo "  down        Stop and remove containers"
	@echo "  restart     Stop then start the stack (localstack mode)"
	@echo "  build       Build all Docker images without starting"
	@echo "  logs        Follow logs for all services (last 100 lines)"
	@echo "  logs-<svc>  Follow logs for a specific service  e.g. make logs-api"
	@echo "  health      Run the healthcheck script"
	@echo "  status      Show container status (alias: ps)"
	@echo "  ps          Alias for status"
	@echo "  traffic     Show recent traffic-generator logs"
	@echo "  test        Run the automated test suite"
	@echo "  shell-<svc> Open a shell inside a running service  e.g. make shell-api"
	@echo "  clean       Stop stack and remove all volumes"
	@echo ""

## up: Start CentralWatch stack (localstack mode)
up:
	@echo "Starting CentralWatch stack (localstack mode)..."
	docker compose up -d --build

## up-aws: Start CentralWatch stack (AWS mode)
up-aws:
	@echo "Starting CentralWatch stack (AWS mode)..."
	docker compose -f docker-compose.yml -f docker-compose.aws.yml --env-file .env up -d --build

## down: Stop and remove containers
down:
	@echo "Stopping CentralWatch stack..."
	docker compose down

## restart: Stop then start the stack
restart: down up

## build: Build all images without starting
build:
	@echo "Building all images..."
	docker compose build

## logs: Follow logs for all services
logs:
	docker compose logs -f --tail=100

## logs-<service>: Follow logs for a specific service
logs-%:
	docker compose logs -f --tail=100 $*

## health: Run the healthcheck script
health:
	@bash scripts/healthcheck.sh

## test: Run automated test suite (on this machine; needs pytest and both packages' requirements)
PYTHON ?= python3
test:
	@echo "Running the demo-app tests..."
	@cd demo-app && AUTH_TOKEN_SECRET=test-only OTEL_SDK_DISABLED=true $(PYTHON) -m pytest tests -q
	@echo "Running the centralwatch-security plugin tests..."
	@AUTH_TOKEN_SECRET=test-only OTEL_SDK_DISABLED=true $(PYTHON) -m pytest centralwatch-security/tests -q

## status: Show container status
status:
	@docker compose ps

## traffic: Show traffic-generator logs
traffic:
	@echo "Traffic generator status:"
	@docker compose logs --tail=50 traffic-generator

## shell-<service>: Open a shell inside a running service
shell-%:
	docker compose exec $* /bin/sh

## clean: Remove all volumes and stop the stack
clean:
	@echo "Removing volumes and stopping stack..."
	docker compose down -v

## ps: Alias for status
ps: status
