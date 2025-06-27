# Jacked Performance Configuration Guide

## Overview

Jacked now includes comprehensive performance optimization settings that allow you to customize scanning behavior based on your system resources and requirements.

## Configuration Location

The performance configuration is automatically included in your `.jacked.yaml` file located at `$HOME/.jacked.yaml`.

## Performance Optimization Levels

You can set a performance optimization level using the `--performance` flag:

```bash
# Basic optimization (minimal resource usage)
jacked --performance=basic alpine:latest

# Balanced optimization (default, good balance of speed and resources)
jacked --performance=balanced alpine:latest

# Aggressive optimization (higher resource usage for maximum speed)
jacked --performance=aggressive alpine:latest

# Maximum optimization (experimental features enabled)
jacked --performance=maximum alpine:latest
```

## Configuration Structure

### Core Performance Settings

```yaml
performance:
  # Scanner concurrency settings
  max_concurrent_scanners: 20      # Number of parallel scanners
  scan_timeout: 5m0s               # Maximum time per scan operation
  
  # Cache settings
  enable_caching: true             # Enable vulnerability result caching
  cache_timeout: 15m0s             # How long to keep cached results
  max_cache_size: 1000             # Maximum number of cached entries
  
  # Database connection settings
  max_db_connections: 40           # Maximum database connections
  max_idle_connections: 20         # Maximum idle connections
  connection_timeout: 30s          # Connection timeout
  
  # Batch processing settings
  batch_size: 50                   # Number of items processed in batches
  enable_batch_processing: true    # Enable batch processing
  
  # Memory management
  enable_memory_optimization: true # Enable memory optimizations
  max_memory_usage_mb: 512         # Maximum memory usage in MB
  
  # Progressive scanning
  enable_progressive_scanning: true # Enable progressive scanning
  component_thresholds:
    small: 50                      # Small BOM threshold
    medium: 200                    # Medium BOM threshold
    large: 500                     # Large BOM threshold
  
  # Metrics and monitoring
  enable_metrics: true             # Enable performance metrics
  metrics_retention: 24h0m0s       # How long to retain metrics
```

### Scanner-Specific Settings

```yaml
performance:
  scanners:
    npm:
      enabled: true                # Enable npm scanner
      timeout: 2m0s               # Scanner timeout
      max_concurrency: 20         # Max concurrent operations
      caching_enabled: true       # Enable caching for this scanner
      priority: 8                 # Scanner priority (1-10)
    
    maven:
      enabled: true
      timeout: 3m0s
      max_concurrency: 20
      caching_enabled: true
      priority: 7
    
    dpkg:
      enabled: true
      timeout: 2m0s
      max_concurrency: 20
      caching_enabled: true
      priority: 9
    
    apk:
      enabled: true
      timeout: 2m0s
      max_concurrency: 20
      caching_enabled: true
      priority: 9
    
    generic:
      enabled: true
      timeout: 4m0s
      max_concurrency: 10
      caching_enabled: true
      priority: 5
```

### Advanced Settings

```yaml
performance:
  # Advanced optimization features
  enable_smart_deduplication: true     # Smart vulnerability deduplication
  deduplication_accuracy_level: 3      # Accuracy level (1-5)
  enable_adaptive_concurrency: true    # Adaptive concurrency based on load
  adaptive_concurrency_threshold: 0.8 # Threshold for adaptive adjustments
  
  # Resource monitoring
  enable_resource_monitoring: true     # Monitor CPU and memory usage
  cpu_threshold: 85                    # CPU usage threshold (%)
  memory_threshold: 80                 # Memory usage threshold (%)
  
  # Experimental features
  enable_experimental_features: false # Enable experimental optimizations
  use_parallel_version_checking: true # Parallel version constraint checking
  enable_predictive_caching: false    # Predictive caching (experimental)
```

## Optimization Levels Explained

### Basic
- Minimal resource usage
- Safe for resource-constrained environments
- Half the normal concurrency
- Basic caching only

### Balanced (Default)
- Good balance of speed and resource usage
- Recommended for most use cases
- Standard concurrency levels
- Full caching enabled

### Aggressive
- Higher resource usage for better performance
- Double concurrency levels
- Shorter timeouts
- Advanced features enabled

### Maximum
- Experimental optimizations
- Maximum concurrency (3x normal)
- All advanced features enabled
- Shortest timeouts
- Best performance but highest resource usage

## Usage Examples

### Scanning with Different Performance Levels

```bash
# For CI/CD environments with limited resources
jacked --performance=basic --ci alpine:latest

# For development with balanced performance
jacked --performance=balanced myapp:latest

# For production scanning with maximum speed
jacked --performance=aggressive --debug myapp:latest

# Experimental maximum performance
jacked --performance=maximum myapp:latest
```

### Advanced Optimized Scanning

For more advanced optimization control, use the `analyze-optimized` command:

```bash
# Use optimized analyzer with custom settings
jacked analyze-optimized --optimization=aggressive --max-concurrency=8 alpine:latest

# Show performance metrics
jacked analyze-optimized --show-metrics --enable-metrics alpine:latest

# Enable profiling for performance analysis
jacked analyze-optimized --enable-profiling alpine:latest
```

## Performance Tuning Tips

1. **For Large Images**: Use `aggressive` or `maximum` optimization levels
2. **For CI/CD**: Use `basic` or `balanced` to avoid resource contention
3. **For Repeated Scans**: Ensure caching is enabled for better performance
4. **For Memory-Constrained Systems**: Lower `max_memory_usage_mb` and `max_concurrent_scanners`
5. **For High-Performance Systems**: Increase `max_concurrent_scanners` and enable experimental features

## Monitoring Performance

Enable metrics to monitor scanning performance:

```bash
jacked --performance=balanced --debug alpine:latest
```

This will show debug output including:
- Applied optimization settings
- Database connection pool status
- Cache hit rates
- Scanning duration
- Resource usage information

## Configuration Validation

Jacked automatically validates your performance configuration and will:
- Apply sensible defaults for invalid values
- Log warnings for configuration issues
- Ensure optimal settings based on your system capabilities

The configuration is automatically adjusted based on your system's CPU count and available resources.
