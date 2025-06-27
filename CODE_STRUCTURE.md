# Jacked - Code Structure Documentation

## Project Overview

Jacked is an open-source vulnerability scanning tool designed to identify and mitigate security risks in Container Images and File Systems. This document provides a comprehensive overview of the codebase structure and organization.

## Top-Level Directory Structure

```
jacked/
├── assets/                     # Static assets (logos, images, examples)
├── cmd/                        # Command-line interface and main entry points
├── docs/                       # Documentation files
├── internal/                   # Internal packages (not exported)
├── pkg/                        # Public packages (exported API)
├── install.sh                  # Installation script
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── Dockerfile                  # Container build configuration
├── README.md                   # Project documentation
├── LICENSE                     # License file
├── NOTICE                      # Third-party notices
├── CODE_OF_CONDUCT.md         # Community guidelines
├── CONTRIBUTING.md            # Contribution guidelines
└── DEVELOPING.md              # Development setup guide
```

## Command Line Interface (`cmd/`)

The CLI is organized around the main application entry point and supporting modules:

```
cmd/jacked/
├── main.go                     # Application entry point
├── build/
│   └── build.go               # Build information and version handling
└── command/                   # CLI command implementations
    ├── root.go                # Main command with optimization flags
    ├── command.go             # Command setup and flag registration
    ├── analyze.go             # Core analysis logic
    ├── build.go               # Version command
    ├── db.go                  # Database management commands
    └── command_test.go        # Command tests
```

### Key CLI Features:
- **Main Command**: `jacked [image]` - Primary vulnerability scanning
- **Database Commands**: `jacked db` - Database information and updates
- **Version Command**: `jacked version` - Build and version information
- **Performance Flags**: `--performance`, `--max-concurrency`, `--enable-metrics`, etc.

## Internal Packages (`internal/`)

Internal packages contain implementation details not exposed to external users:

```
internal/
├── cli/
│   └── cli.go                 # Legacy CLI interface (backward compatibility)
├── compare/                   # Vulnerability comparison logic
│   ├── compare.go             # Main comparison logic
│   ├── constraint.go          # Version constraint handling
│   ├── cpe.go                 # CPE (Common Platform Enumeration) matching
│   ├── apk.go                 # Alpine package comparison
│   ├── deb.go                 # Debian package comparison
│   ├── maven.go               # Maven artifact comparison
│   └── generic.go             # Generic package comparison
├── db/                        # Database operations and management
│   ├── db.go                  # Core database interface
│   ├── checker.go             # Database health checking
│   ├── update.go              # Database update logic
│   ├── apk_sec_db.go          # Alpine security database
│   ├── deb_sec_tracker.go     # Debian security tracker
│   ├── ghsa.go                # GitHub Security Advisory database
│   └── nvd.go                 # National Vulnerability Database
├── helper/                    # Utility functions
│   ├── component.go           # Component manipulation helpers
│   ├── constraint.go          # Version constraint utilities
│   ├── file.go                # File system operations
│   ├── image.go               # Container image utilities
│   ├── json.go                # JSON processing utilities
│   ├── regex.go               # Regular expression utilities
│   ├── xml.go                 # XML processing utilities
│   └── yaml.go                # YAML processing utilities
├── log/
│   └── log.go                 # Logging configuration and utilities
├── presenter/
│   └── presenter.go           # Output formatting and presentation
└── tea/                       # Terminal UI components (Bubble Tea)
    ├── progress/
    │   ├── progress.go         # Progress bar implementation
    │   └── tui.go             # Terminal UI for progress
    ├── spinner/
    │   └── spinner.go         # Loading spinner implementation
    └── table/
        └── table.go           # Table display implementation
```

## Public Packages (`pkg/`)

Public packages provide the main API and functionality:

```
pkg/
├── analyzer/                  # Vulnerability analysis engine
│   └── cdx.go                 # CycloneDX BOM analysis
├── ci/                        # Continuous Integration support
│   ├── ci.go                  # CI/CD integration logic
│   ├── cdx.go                 # CycloneDX CI processing
│   ├── evaluate.go            # Result evaluation
│   ├── match.go               # Vulnerability matching
│   ├── tally.go               # Result tallying
│   └── vex.go                 # VEX (Vulnerability Exchange) support
├── config/                    # Configuration management
│   └── config.go              # Application configuration
├── db/                        # Database interface
│   └── db.go                  # Public database API
├── model/                     # Data models
│   ├── cdx/
│   │   └── v3.go              # CycloneDX v3 models
│   └── vex/                   # VEX data models
├── scan/                      # Vulnerability scanning engine (REFACTORED)
│   ├── core/                  # Core scanning interfaces and engine
│   │   ├── interfaces.go      # Main interfaces (Scanner, ExecutionStrategy, etc.)
│   │   ├── engine.go          # ScanEngine orchestrator
│   │   ├── strategies.go      # Execution strategies (Sequential/Concurrent)
│   │   ├── cache.go           # Caching implementation
│   │   ├── metrics.go         # Metrics collection
│   │   ├── deduplicator.go    # Smart vulnerability deduplication
│   │   └── filters.go         # Component filtering
│   ├── base/                  # Base scanner implementations
│   │   ├── scanner.go         # ComponentScanner base class
│   │   ├── version_parsers.go # Version parsing for all package types
│   │   ├── providers.go       # Vulnerability data providers
│   │   └── wrappers.go        # Version checker wrappers
│   ├── factory/               # Scanner factory pattern
│   │   └── scanner_factory.go # Factory for creating scanners
│   ├── scan.go                # Backward compatible manager interface
│   ├── advanced_manager.go    # Legacy advanced manager (deprecated)
│   ├── generic/               # Generic package scanner
│   │   └── generic_scanner.go
│   ├── golang/                # Go module scanner
│   │   └── golang_scanner.go
│   ├── maven/                 # Maven artifact scanner
│   │   └── maven_scanner.go
│   ├── npm/                   # NPM package scanner
│   │   ├── npm_scanner.go
│   │   └── optimized_scanner.go
│   ├── python/                # Python package scanner
│   │   └── python_scanner.go
│   ├── rubygem/               # Ruby gem scanner
│   │   └── rubygem_scanner.go
│   └── os/                    # Operating system package scanners
│       ├── apk/
│       │   └── apk_scanner.go # Alpine Package Keeper
│       ├── dpkg/
│       │   └── dpkg_scanner.go # Debian packages
│       └── rpm/
│           └── rpm_scanner.go  # Red Hat packages
├── types/                     # Type definitions
│   ├── config.go              # Configuration types
│   ├── parameters.go          # Parameter structures
│   ├── severities.go          # Vulnerability severity definitions
│   └── vulnerability.go       # Vulnerability data structures
└── version/                   # Version handling and constraints
    ├── version.go             # Common version interface
    ├── apk_version.go         # Alpine package versions
    ├── apk_constraint.go      # Alpine version constraints
    ├── dpkg_version.go        # Debian package versions
    ├── dpkg_constraint.go     # Debian version constraints
    ├── gem_version.go         # Ruby gem versions
    ├── gem_contraint.go       # Ruby gem constraints
    ├── go_version.go          # Go module versions
    ├── go_constraint.go       # Go version constraints
    ├── jvm_version.go         # JVM/Java versions
    ├── jvm_constraint.go      # JVM version constraints
    ├── maven_version.go       # Maven artifact versions
    ├── maven_contraint.go     # Maven version constraints
    ├── npm_version.go         # NPM package versions
    ├── npm_constraint.go      # NPM version constraints
    ├── pep440_version.go      # Python PEP440 versions
    ├── pep440_constraint.go   # Python version constraints
    ├── rpm_version.go         # RPM package versions
    ├── rpm_constraint.go      # RPM version constraints
    ├── semantic_version.go    # Semantic versioning
    └── semantic_constraint.go # Semantic version constraints
```

## Data Flow Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Commands  │───▶│   Analyzer       │───▶│   ScanEngine    │
│   (cmd/)        │    │   (pkg/analyzer) │    │   (pkg/scan)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Diggity       │◀───│   BOM Generation │    │   Scanners      │
│   (External)    │    │   (internal/cli) │    │   (pkg/scan/*/) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Presenter     │◀───│   Vulnerabilities│◀───│   Databases     │
│   (internal/)   │    │   (pkg/model)    │    │   (internal/db) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Key Design Patterns

### 1. **Factory Pattern**
- **Location**: `pkg/scan/factory/`
- **Purpose**: Creates scanners consistently without code duplication
- **Benefits**: Easy to add new scanner types, centralized configuration

### 2. **Strategy Pattern**
- **Location**: `pkg/scan/core/strategies.go`
- **Purpose**: Different execution strategies (sequential vs concurrent)
- **Benefits**: Flexible execution models, easy to add new strategies

### 3. **Interface Segregation**
- **Location**: `pkg/scan/core/interfaces.go`
- **Purpose**: Clean separation of concerns with focused interfaces
- **Benefits**: Better testability, loose coupling, easy mocking

### 4. **Dependency Injection**
- **Location**: Throughout `pkg/scan/core/` and `pkg/scan/base/`
- **Purpose**: Pluggable components (cache, metrics, deduplication)
- **Benefits**: Easy testing, flexible configuration, runtime behavior changes

### 5. **Template Method**
- **Location**: `pkg/scan/base/scanner.go`
- **Purpose**: Common scanning logic with customizable vulnerability retrieval
- **Benefits**: Code reuse, consistent behavior, easy to extend

## Database Integration

The application integrates with multiple vulnerability databases:

```
┌─────────────────┐    ┌──────────────────┐
│   NVD           │───▶│                  │
│   (nvd.go)      │    │                  │
├─────────────────┤    │                  │
│   GHSA          │───▶│   Database       │
│   (ghsa.go)     │    │   Aggregator     │
├─────────────────┤    │   (db.go)        │
│   Alpine SecDB  │───▶│                  │
│   (apk_sec_db)  │    │                  │
├─────────────────┤    │                  │
│   Debian Tracker│───▶│                  │
│   (deb_sec_*)   │    │                  │
└─────────────────┘    └──────────────────┘
```

## Configuration Management

Configuration follows a hierarchical approach:

1. **Default Configuration**: Built-in defaults
2. **Config File**: `~/.jacked.yaml` or custom path
3. **Environment Variables**: Override config file
4. **Command Line Flags**: Highest priority

## Performance Optimization

The codebase includes several performance optimizations:

- **Intelligent Scanner Selection**: Only run relevant scanners based on component types
- **Concurrent Execution**: Parallel scanner execution with controlled concurrency
- **Caching**: Multi-level caching with TTL support
- **Component Filtering**: Pre-filter components to reduce processing
- **Smart Deduplication**: Enhanced deduplication with completeness scoring
- **Resource Management**: Context-based cancellation and timeout handling

## Testing Structure

```
*_test.go files are co-located with source files
cmd/jacked/command/command_test.go    # CLI command tests
pkg/version/version_test.go           # Version handling tests
```

## Extension Points

The architecture provides several extension points:

1. **New Scanners**: Implement `core.Scanner` interface
2. **Custom Execution**: Implement `core.ExecutionStrategy` interface
3. **Custom Caching**: Implement `core.CacheProvider` interface
4. **Custom Metrics**: Implement `core.MetricsCollector` interface
5. **Custom Deduplication**: Implement `core.VulnerabilityDeduplicator` interface

## Dependencies

Key external dependencies:

- **CycloneDX**: BOM format handling
- **Diggity**: Container image and filesystem scanning
- **Bubble Tea**: Terminal UI components
- **Cobra**: CLI framework
- **Various version libraries**: Package-specific version handling

This architecture provides a clean, maintainable, and extensible foundation for vulnerability scanning while maintaining backward compatibility with existing functionality.
