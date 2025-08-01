.PHONY: test clean fmt lint build-caddy

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

# Build Caddy with this plugin using xcaddy
build-caddy:
	~/go/bin/xcaddy build --with github.com/DoMaLo/caddy-regru=./

# Run Caddy with example config (requires build-caddy first)
run-example: build-caddy
	set -a && source ./.env && set +a && ./caddy run --config example/Caddyfile

# Install xcaddy if not present
install-xcaddy:
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest