# Caddy DNS Provider for reg.ru

This package contains a DNS provider for [Caddy](https://caddyserver.com/) that allows automatic SSL certificate generation using reg.ru DNS API.

## Features

- Automatic SSL certificate generation using ACME DNS-01 challenge
- Support for reg.ru API credentials

## Installation

### Prerequisites

Install xcaddy:

```bash  
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest  
```

### Build Caddy with this plugin

```bash
xcaddy build --with github.com/DoMaLo/caddy-regru
```

Or if you're developing locally:

```bash
git clone https://github.com/DoMaLo/caddy-regru
cd caddy-regru
xcaddy build --with github.com/DoMaLo/caddy-regru=./
```

## Configuration

### Environment Variables

Set your reg.ru credentials as environment variables:

```bash
export REGRU_USERNAME="your-username"
export REGRU_PASSWORD="your-password"
```

### Caddyfile

```caddyfile
*.example.com {
    tls {
        dns regru {
            username {$REGRU_USERNAME}
            password {$REGRU_PASSWORD}
        }
    }
    respond "Hello from wildcard domain"
}
```

## Development

### Running Tests

```bash
make test
```

### Running Tests with Coverage

```bash
make test-coverage
```

### Building Caddy with Plugin

```bash
make build-caddy
```

### Running Example

```bash
make run-example
```
