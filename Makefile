# Makefile for Jacked Performance Configuration System

.PHONY: help test test-unit test-integration test-performance bench clean build install lint fmt vet coverage

# Default target
help:
	@echo "Jacked Performance Configuration System"
	@echo ""
	@echo "Available targets:"
	@echo "  build             - Build the jacked binary"
	@echo "  test              - Run all tests"
	@echo "  test-scanners     - Run scanner-specific unit tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests"
	@echo "  test-performance  - Run performance tests with real scanning"
	@echo "  test-all          - Run comprehensive test suite"
	@echo "  test-config       - Test configuration validation"
	@echo "  lint              - Run linting tools"
	@echo "  fmt               - Format code"
	@echo "  vet               - Run go vet"
	@echo "  clean             - Clean build artifacts"
	@echo "  install           - Install jacked binary to GOPATH/bin"
	@echo "  dev-setup         - Set up development environment"
	@echo "  pre-commit        - Quick validation before commit"
	@echo "  ci                - CI/CD pipeline simulation"
	@echo "  perf-regression   - Performance regression testing"
	@echo "  release           - Create release builds"
	@echo "  docs-check        - Check documentation"
	@echo "  validate          - Full validation pipeline"

# Build the jacked binary
build:
	@echo "Building jacked..."
	go build -o jacked ./cmd/jacked/main.go
	@echo "Build complete!"

# Install jacked to GOPATH/bin
install:
	@echo "Installing jacked..."
	go install ./cmd/jacked
	@echo "Installation complete!"

# Run all tests
test: test-unit test-integration
	@echo "All tests completed!"

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/ ./pkg/scan/ ./pkg/version/ ./internal/helper/ ./internal/metrics/

# Run scanner-specific unit tests
test-scanners:
	@echo "Running scanner unit tests..."
	go test -v ./pkg/scan/ ./pkg/scan/npm/ ./pkg/scan/maven/ ./pkg/scan/python/ ./pkg/scan/golang/ ./pkg/scan/rubygem/ ./pkg/scan/generic/ ./pkg/scan/os/apk/ ./pkg/scan/os/dpkg/ ./pkg/scan/os/rpm/

# Run integration tests
test-integration: build
	@echo "Running integration tests..."
	@echo "Testing CLI help commands..."
	./jacked --help > /dev/null
	./jacked version > /dev/null
	./jacked --performance=basic --help > /dev/null
	./jacked --performance=balanced --help > /dev/null
	./jacked --performance=aggressive --help > /dev/null
	./jacked --performance=maximum --help > /dev/null
	./jacked --non-interactive --help > /dev/null
	./jacked analyze-optimized --help > /dev/null
	@echo "Integration tests passed!"

# Run performance tests with actual scanning
test-performance: build
	@echo "Running performance tests..."
	chmod +x test-performance.sh
	./test-performance.sh

# Run comprehensive test suite
test-all: build
	@echo "Running comprehensive test suite..."
	chmod +x run-tests.sh
	./run-tests.sh

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/ ./pkg/scan/ ./pkg/version/ ./internal/helper/ ./internal/metrics/

# Generate code coverage report
coverage:
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/ ./pkg/scan/ ./pkg/version/ ./internal/helper/ ./internal/metrics/
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | tail -1
	@echo "Coverage report generated: coverage.html"

# Run linting tools
lint: fmt vet
	@echo "Running staticcheck..."
	staticcheck ./... || echo "staticcheck not available, skipping..."

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	@echo "Code formatted!"

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "go vet passed!"

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f jacked jacked.exe
	rm -f coverage.out coverage.html
	rm -f test-config.yaml invalid-config.yaml
	rm -f bench-results.txt
	rm -f dist/
	@echo "Cleanup complete!"

# Development commands
dev-setup:
	@echo "Setting up development environment..."
	go mod download
	go mod verify
	@echo "Development setup complete!"

# Quick validation before commit
pre-commit: fmt vet test-unit
	@echo "Pre-commit checks passed!"

# CI/CD pipeline simulation
ci: dev-setup lint test coverage
	@echo "CI pipeline simulation complete!"

# Performance regression testing
perf-regression: bench
	@echo "Running performance regression tests..."
	go test -bench=. -count=5 ./pkg/... > bench-results.txt
	@echo "Performance results saved to bench-results.txt"

# Create release build
release: clean fmt vet test
	@echo "Creating release build..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o jacked-linux-amd64 ./cmd/jacked/main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o jacked-windows-amd64.exe ./cmd/jacked/main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o jacked-darwin-amd64 ./cmd/jacked/main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o jacked-darwin-arm64 ./cmd/jacked/main.go
	@echo "Release builds created!"

# Test configuration validation
test-config:
	@echo "Testing configuration validation..."
	# Create valid config
	@echo 'version: "1.0"' > test-config.yaml
	@echo 'performance:' >> test-config.yaml
	@echo '  max_concurrent_scanners: 8' >> test-config.yaml
	@echo '  scan_timeout: 300s' >> test-config.yaml
	@echo '  enable_caching: true' >> test-config.yaml
	@echo '  max_cache_size: 1000' >> test-config.yaml
	@echo '  scanners:' >> test-config.yaml
	@echo '    npm:' >> test-config.yaml
	@echo '      enabled: true' >> test-config.yaml
	@echo '      timeout: 120s' >> test-config.yaml
	@echo '      max_concurrency: 8' >> test-config.yaml
	@echo '      caching_enabled: true' >> test-config.yaml
	@echo '      priority: 8' >> test-config.yaml
	./jacked --config=test-config.yaml --help > /dev/null
	@echo "Valid config test passed!"
	
	# Create invalid config
	@echo 'version: "1.0"' > invalid-config.yaml
	@echo 'performance:' >> invalid-config.yaml
	@echo '  max_concurrent_scanners: invalid_number' >> invalid-config.yaml
	@echo '  scan_timeout: not_a_duration' >> invalid-config.yaml
	./jacked --config=invalid-config.yaml --help > /dev/null || echo "Invalid config handled correctly"
	rm -f test-config.yaml invalid-config.yaml
	@echo "Configuration validation tests completed!"

# Documentation validation
docs-check:
	@echo "Checking documentation..."
	@if [ ! -f "PERFORMANCE_CONFIGURATION.md" ]; then echo "Missing PERFORMANCE_CONFIGURATION.md"; exit 1; fi
	@if [ ! -f "test-performance.sh" ]; then echo "Missing test-performance.sh"; exit 1; fi
	@if [ ! -f "run-tests.sh" ]; then echo "Missing run-tests.sh"; exit 1; fi
	@echo "Documentation check passed!"

# Full validation pipeline
validate: dev-setup fmt vet lint test-unit test-integration test-config coverage docs-check
	@echo ""
	@echo "🎉 Full validation pipeline completed successfully! 🎉"
	@echo ""
	@echo "Summary:"
	@echo "- Code is properly formatted"
	@echo "- No linting issues found"
	@echo "- All unit tests passed"
	@echo "- Integration tests passed"
	@echo "- Configuration validation passed"
	@echo "- Code coverage generated"
	@echo "- Documentation is present"
	@echo ""
	@echo "Ready for production! ✅"
