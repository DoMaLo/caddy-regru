# Changelog

## [v0.1.1] - 2025-02-26

### Fixed
- REG.RU API `zone/add_txt`: use parameter `text` instead of `content`, remove redundant `record_type` (per official API docs)

## [v0.1.0] - 2025-11-26

### Added
- Support for wildcard zones (`*.test.com`, `*.local.test.com`)
- Comprehensive zone parsing tests (`provider_zone_test.go`)
- Improved Makefile with automatic xcaddy installation
- Structured JSON parsing for GetZones API response
- Constants for User-Agent and BaseURL

### Changed
- Improved zone parsing logic with wildcard support
- Replaced Russian comments with English in `internal/client.go`
- Enhanced error handling in GetZones with structured parsing
- Better subdomain computation for multi-level domains
- Makefile now automatically installs xcaddy if missing

### Fixed
- Fixed Replacer usage in Provision method
- Improved zone matching algorithm for subdomains
- Better handling of edge cases in getSubdomain function

### Technical
- Removed backward compatibility fallback in GetZones (clean structured parsing only)
- Added helper functions for zone normalization
- Improved logging and error messages

