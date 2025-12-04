.PHONY: test clean fmt lint build-caddy install-xcaddy deps run-example help

# Default target
.DEFAULT_GOAL := help

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -f caddy coverage.out coverage.html

# Install dependencies
deps:
	go mod tidy
	go mod download

# Install xcaddy if not present
install-xcaddy:
	@if ! command -v xcaddy >/dev/null 2>&1 && [ ! -f ~/go/bin/xcaddy ]; then \
		echo "Installing xcaddy..."; \
		go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; \
	else \
		echo "xcaddy is already installed"; \
	fi

# Build Caddy with this plugin using xcaddy
build-caddy: install-xcaddy
	@echo "Building Caddy with regru plugin..."
	@if command -v xcaddy >/dev/null 2>&1; then \
		xcaddy build --with github.com/DoMaLo/caddy-regru=./; \
	elif [ -f ~/go/bin/xcaddy ]; then \
		~/go/bin/xcaddy build --with github.com/DoMaLo/caddy-regru=./; \
	else \
		echo "Error: xcaddy not found. Run 'make install-xcaddy' first."; \
		exit 1; \
	fi
	@echo "Build complete! Binary: ./caddy"

# Run Caddy with example config (requires build-caddy first)
run-example: build-caddy
	@if [ ! -f .env ]; then \
		echo "Warning: .env file not found. Create it with REG_USER and REG_PASS variables."; \
	fi
	@if [ ! -f example/Caddyfile.test ]; then \
		echo "Warning: example/Caddyfile.test not found. Using example/Caddyfile instead."; \
		set -a && source ./.env && set +a && ./caddy run --config example/Caddyfile; \
	else \
		set -a && source ./.env && set +a && ./caddy run --config example/Caddyfile.test; \
	fi

# Help target
help:
	@echo "Available targets:"
	@echo "  make install-xcaddy  - Install xcaddy tool"
	@echo "  make deps            - Download Go dependencies"
	@echo "  make build-caddy     - Build Caddy with regru plugin"
	@echo "  make run-example     - Build and run Caddy with example config"
	@echo "  make test            - Run tests"
	@echo "  make test-coverage   - Run tests with coverage report"
	@echo "  make fmt             - Format code"
	@echo "  make lint            - Run linter"
	@echo "  make clean           - Remove build artifacts"