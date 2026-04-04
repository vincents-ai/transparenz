.PHONY: build test clean install help

# Variables
BINARY_NAME=transparenz
BUILD_DIR=build
CMD_DIR=cmd/transparenz
VERSION?=0.1.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

help: ## Show this help message
	@echo "Transparenz CLI - Week 1-2 Implementation"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the transparenz binary
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: ## Build for multiple platforms
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@echo "Built binaries:"
	@ls -lh $(BUILD_DIR)/

test: ## Run tests with race detector
	go test -race -v ./...

test-short: ## Run tests without integration tests
	go test -race -short -v ./...

test-coverage: ## Run tests and report coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-coverage-html: test-coverage ## Open coverage report in browser
	go tool cover -html=coverage.out

fmt: ## Format Go code
	go fmt ./...
	gofmt -s -w .

lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	go clean

install: build ## Install binary to $GOPATH/bin
	@echo "Installing to $(GOPATH)/bin/$(BINARY_NAME)..."
	go install $(LDFLAGS) ./$(CMD_DIR)

deps: ## Download Go module dependencies
	go mod download
	go mod tidy

# Development commands
dev: ## Run in development mode
	go run ./$(CMD_DIR) --help

demo-generate: build ## Demo: Generate SBOM for transparenz-go itself
	@echo "Generating SBOM for transparenz-go..."
	$(BUILD_DIR)/$(BINARY_NAME) generate . --format spdx --output $(BUILD_DIR)/transparenz-sbom.json --verbose
	@echo ""
	@echo "SBOM generated: $(BUILD_DIR)/transparenz-sbom.json"
	@wc -l $(BUILD_DIR)/transparenz-sbom.json

demo-bsi-check: demo-generate ## Demo: Run BSI compliance check
	@echo "Running BSI TR-03183-2 compliance check..."
	$(BUILD_DIR)/$(BINARY_NAME) bsi-check $(BUILD_DIR)/transparenz-sbom.json --output $(BUILD_DIR)/bsi-report.json

demo-all: build ## Run all demos
	@echo "=== Demo 1: Help ==="
	$(BUILD_DIR)/$(BINARY_NAME) --help
	@echo ""
	@echo "=== Demo 2: Generate Command Help ==="
	$(BUILD_DIR)/$(BINARY_NAME) generate --help
	@echo ""
	@echo "=== Demo 3: Generate SBOM ==="
	$(BUILD_DIR)/$(BINARY_NAME) generate . --format spdx --output $(BUILD_DIR)/transparenz-sbom.json
	@echo ""
	@echo "=== Demo 4: BSI Compliance Check ==="
	$(BUILD_DIR)/$(BINARY_NAME) bsi-check $(BUILD_DIR)/transparenz-sbom.json
	@echo ""
	@echo "=== Demo 5: List Command (stub) ==="
	$(BUILD_DIR)/$(BINARY_NAME) list || true

# Docker
docker-build: ## Build Docker image
	docker build -t transparenz:$(VERSION) .

docker-run: docker-build ## Run in Docker container
	docker run --rm transparenz:$(VERSION) --help
