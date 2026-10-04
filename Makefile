SHELL := /bin/sh
BIN := bin
BINARY := $(BIN)/oauth-server
PKG := ./...
GO ?= go
COMPOSE ?= docker compose

.DEFAULT_GOAL := help

.PHONY: help build run test test-race test-short cover bench vet fmt lint lint-fix tidy dist \
        migrate-up migrate-down migrate-status migrate-force migrate-create \
        docker-up docker-down \
        schema-apply schema-reset schema-test schema-roundtrip \
        deps-up deps-down deps-reset up down psql redis-cli mailhog clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary
	$(GO) build -trimpath -o $(BINARY) ./cmd/server

run: ## Run the server with live reload of nothing (plain go run)
	$(GO) run ./cmd/server

test: ## Full test suite: race detector, shuffled order, no cache
	$(GO) test -race -shuffle=on -count=1 $(PKG)

test-race: ## Run tests with race detector
	$(GO) test -race -count=1 $(PKG)

test-short: ## Fast subset, skips integration tests
	$(GO) test -short $(PKG)

cover: ## Coverage report to stdout
	$(GO) test -race -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out

bench: ## Run benchmarks
	$(GO) test -bench=. -benchmem $(PKG)

vet: ## go vet
	$(GO) vet $(PKG)

fmt: ## Format all Go source
	gofmt -l -w .

lint: ## Run golangci-lint
	golangci-lint run

lint-fix: ## Run golangci-lint with autofix
	golangci-lint run --fix

tidy: ## Tidy and verify module graph
	$(GO) mod tidy
	$(GO) mod verify

dist: ## Static binary for the distroless runtime image
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/server

migrate-up: ## Apply all pending migrations
	$(GO) run ./cmd/migrate -direction up

migrate-down: ## Roll back exactly one migration
	$(GO) run ./cmd/migrate -direction down -steps 1

migrate-status: ## Show current migration version
	$(GO) run ./cmd/migrate -direction status

migrate-force: ## Force migration version (VERSION=n)
	$(GO) run ./cmd/migrate -direction force -version $(VERSION)

migrate-create: ## Create a new migration (NAME=add_thing)
	$(GO) run ./cmd/migrate -direction create -name $(NAME)

docker-up: ## Start dependencies and app
	$(COMPOSE) up -d

docker-down: ## Stop the full stack
	$(COMPOSE) down

# The migrate-* targets above run ./cmd/migrate against the configured database.
# The schema-* targets below drive psql inside the container directly so they
# can test the raw SQL migrations in isolation.

schema-apply: ## Apply migrations via psql (requires an EMPTY database)
	$(COMPOSE) up -d postgres
	$(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	  -f /dev/stdin < migrations/001_initial_schema.up.sql
	@echo "applied migrations/001_initial_schema.up.sql"

# Every CREATE TABLE in the migration is deliberately bare, with no IF NOT
# EXISTS guard. A migration that silently no-ops against a drifted database is
# worse than one that refuses, so re-applying over an existing schema is an
# error by design. Use schema-reset to get to a known state; it is idempotent
# because the down migration uses DROP TABLE IF EXISTS throughout.

schema-reset: ## Roll the schema all the way back, then re-apply it
	$(COMPOSE) up -d postgres
	$(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	  -f /dev/stdin < migrations/001_initial_schema.down.sql
	$(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	  -f /dev/stdin < migrations/001_initial_schema.up.sql
	@echo "schema reset"

schema-test: schema-reset ## Assert every CHECK and security index
	$(COMPOSE) exec -T postgres psql -U oauth -d oauth < test/db/constraints.sql

schema-roundtrip: ## Apply, roll back and re-apply 3x, asserting no tables leak
	$(COMPOSE) up -d postgres
	$(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	  -f /dev/stdin < migrations/001_initial_schema.down.sql
	@for i in 1 2 3; do \
	  $(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	    -f /dev/stdin < migrations/001_initial_schema.up.sql || exit 1; \
	  n=`$(COMPOSE) exec -T postgres psql -t -A -U oauth -d oauth \
	      -c "SELECT count(*) FROM pg_tables WHERE schemaname='public';"`; \
	  echo "round $$i up   -> $$n tables"; \
	  $(COMPOSE) exec -T postgres psql -q -v ON_ERROR_STOP=1 -U oauth -d oauth \
	    -f /dev/stdin < migrations/001_initial_schema.down.sql || exit 1; \
	  n=`$(COMPOSE) exec -T postgres psql -t -A -U oauth -d oauth \
	      -c "SELECT count(*) FROM pg_tables WHERE schemaname='public';"`; \
	  echo "round $$i down -> $$n tables"; \
	  test "$$n" = "0" || { echo "down migration leaked tables"; exit 1; }; \
	done

deps-up: ## Start postgres, redis and mailhog only
	$(COMPOSE) up -d postgres redis mailhog

deps-down: ## Stop the dependency containers
	$(COMPOSE) down

deps-reset: ## Stop dependencies and DESTROY the database volume
	$(COMPOSE) down -v

up: ## Build and run the full stack
	$(COMPOSE) up --build

down: ## Stop the full stack
	$(COMPOSE) down

psql: ## Open a psql shell against the dev database
	$(COMPOSE) exec postgres psql -U oauth -d oauth

redis-cli: ## Open a redis-cli shell
	$(COMPOSE) exec redis redis-cli

mailhog: ## Print the Mailhog UI URL
	@echo "Mailhog UI: http://localhost:8025"

clean: ## Remove build artefacts
	rm -rf $(BIN) coverage.out