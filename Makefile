# Makefile for scanoss — tests, linting, and common dev tasks.

GO               ?= go
GOLANGCI_LINT    ?= golangci-lint
GOLANGCI_VERSION ?= v2.14.0
PKGS          ?= ./...
BIN           ?= scanoss-cli
GOFMT_FILES   := $(shell find . -name '*.go' -not -path './vendor/*')

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run all unit tests
	$(GO) test $(PKGS)

.PHONY: test-race
test-race: ## Run tests with the race detector
	$(GO) test -race -count=1 $(PKGS)

.PHONY: cover
cover: ## Run tests and write a coverage profile (coverage.out)
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: cover-html
cover-html: cover ## Generate an HTML coverage report (coverage.html)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Wrote coverage.html"

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(PKGS)

.PHONY: fmt
fmt: ## Format all Go files in place (gofmt + import grouping)
	$(GOLANGCI_LINT) fmt

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is not gofmt-clean
	@unformatted=$$(gofmt -l $(GOFMT_FILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: lint-install
lint-install: ## Install the pinned golangci-lint version
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_VERSION)/install.sh \
		| sh -s -- -b $(shell $(GO) env GOPATH)/bin $(GOLANGCI_VERSION)

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run --timeout=5m

.PHONY: build
build: ## Build the CLI binary
	$(GO) build -o $(BIN) ./cmd/scanoss-cli

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

# OpenAPI model types are consumed from the published SDK module
# github.com/scanoss/scanoss.api-sdk (pinned in go.mod). To update them,
# bump that dependency: `go get github.com/scanoss/scanoss.api-sdk@latest`.

.PHONY: check
check: fmt-check vet lint test ## Run fmt-check, vet, lint, and tests (local CI)

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BIN) coverage.out coverage.html
