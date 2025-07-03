# GitHub Actions Workflows

This directory contains the GitHub Actions workflows for the Jacked project. The workflows are designed to provide comprehensive CI/CD coverage with modern best practices.

## Workflows Overview

### 🚀 Main CI/CD Pipeline (`performance-tests.yml`)

This is the primary workflow that handles building, testing, and deployment. It includes:

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches  
- Daily scheduled runs at 2 AM UTC for dependency checks
- Manual workflow dispatch with options

**Jobs:**

1. **Lint & Code Quality** 🔍
   - Go formatting checks
   - `go vet` analysis
   - `staticcheck` linting
   - `govulncheck` vulnerability scanning
   - `gosec` security analysis with SARIF upload

2. **Test Matrix** 🧪
   - Tests across multiple OS (Ubuntu, Windows, macOS)
   - Multiple Go versions (1.22, 1.23)
   - Coverage reporting to Codecov
   - Benchmark execution
   - CLI functionality testing

3. **Integration Tests** 🔗
   - Real Docker image scanning scenarios
   - Configuration file testing
   - Error handling validation
   - Multi-architecture compatibility

4. **Docker Build & Security Scan** 🐳
   - Multi-platform builds (amd64, arm64)
   - Trivy security scanning
   - Container registry publishing
   - Multi-stage build testing

5. **Performance Monitoring** 📈
   - Comprehensive benchmarking
   - CPU and memory profiling
   - Performance regression detection
   - Historical trend analysis

6. **Release Management** 📦
   - Automated releases on version tags
   - Enhanced changelog generation
   - SBOM (Software Bill of Materials) creation
   - Digital signing preparation

7. **Dependency Updates** 🔄
   - Automated dependency checks (scheduled)
   - Security vulnerability scanning
   - Automated pull request creation

8. **Build Summary** 📊
   - Comprehensive pipeline status
   - Artifact tracking
   - Duration reporting

### 🔒 Security Analysis (`codeql.yml`)

Dedicated security scanning workflow:
- **CodeQL Analysis** for static security analysis
- Runs on push, PR, and weekly schedule
- Integrates with GitHub Security tab
- Language-specific analysis for Go

## Workflow Features

### 🎯 Modern Best Practices

- **Concurrency Control**: Automatic cancellation of superseded runs
- **Path Filtering**: Skip unnecessary runs for documentation changes
- **Caching**: Aggressive caching for Go modules and Docker layers
- **Security**: SARIF upload, vulnerability scanning, security-first mindset
- **Efficiency**: Smart matrix reduction and conditional job execution

### 🛠 Manual Controls

The main workflow supports manual triggering with options:
- `skip_tests`: Skip test execution for faster iterations
- `performance_only`: Run only performance benchmarks

### 📊 Monitoring & Observability

- Detailed job summaries in GitHub UI
- Performance trend tracking
- Artifact retention policies
- Comprehensive logging and error reporting

### 🚀 Performance Optimizations

- **Build Caching**: Go module and Docker layer caching
- **Matrix Optimization**: Reduced test matrix while maintaining coverage
- **Conditional Execution**: Jobs run only when needed
- **Parallel Execution**: Maximum parallelization where safe

## Configuration

### Required Secrets

The workflows use these optional secrets:
- `CODECOV_TOKEN`: For enhanced Codecov integration (optional for public repos)

### Environment Variables

Key environment variables:
- `GO_VERSION`: Go version for builds and tests
- `CGO_ENABLED`: Disabled for static binaries
- `REGISTRY`: Container registry URL
- `IMAGE_NAME`: Docker image name

## Maintenance

### Updating Workflows

1. **Dependencies**: GitHub Actions are pinned to major versions for security
2. **Go Versions**: Update `GO_VERSION` in environment variables
3. **Tool Versions**: Update tool installations in respective steps

### Adding New Jobs

When adding new jobs:
1. Follow the existing naming convention
2. Add appropriate `needs` dependencies
3. Update the summary job to include the new job
4. Consider timeout and resource requirements

### Security Considerations

- All external actions are pinned to specific versions
- Minimal permissions are granted to each job
- Secrets are only used where absolutely necessary
- Security scanning is integrated at multiple levels

## Troubleshooting

### Common Issues

1. **Cache Misses**: Check cache key consistency across jobs
2. **Permission Errors**: Verify job permissions are correctly set
3. **Timeout Issues**: Adjust timeout values for long-running operations
4. **Matrix Failures**: Review matrix exclusions and conditional logic

### Debugging

- Use `debug` input in manual workflow dispatch for verbose logging
- Check artifact uploads for detailed logs and reports
- Review job summaries for quick status overview

## Contributing

When modifying workflows:
1. Test changes in a fork first
2. Document any new features or requirements
3. Update this README if workflow structure changes
4. Consider backward compatibility for existing integrations
