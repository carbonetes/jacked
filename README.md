<p align="center">
  <img src="assets/jacked-logo.svg" alt="Jacked" style="display: block; margin-left: auto; margin-right: auto; width: 50%; margin-bottom: 5%;">
</p>

<div align="center">

[![Github All Releases](https://img.shields.io/github/downloads/carbonetes/jacked/total.svg)]()
[![Go Report Card](https://goreportcard.com/badge/github.com/carbonetes/jacked)](https://goreportcard.com/report/github.com/carbonetes/jacked)
[![GitHub release](https://img.shields.io/github/release/carbonetes/jacked.svg)](https://github.com/carbonetes/jacked/releases/latest)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/carbonetes/jacked.svg)](https://github.com/carbonetes/jacked)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/carbonetes/jacked/blob/main/LICENSE)

Jacked is an open-source vulnerability scanning tool designed to help you identify and mitigate security risks in your [Container Images](#scanning-docker-images) and [File Systems](#scanning-code-repositories).

  <img src="assets/jacked_sample.png" style="width: 65%;">
</div>

## Integration with Diggity

**Jacked** works seamlessly with [Diggity](https://github.com/carbonetes/diggity), our powerful tool for generating Software Bill of Materials (SBOM). Together, they provide a comprehensive solution for securing your software development process.

## Key Features:

- **Comprehensive Vulnerability Scanning**: Jacked thoroughly examines your container images and file systems to pinpoint potential security risks and vulnerabilities. This comprehensive approach ensures the robustness and security of your deployed container images and codebases.
- **Intelligent Configuration Management**: Jacked features automatic configuration validation, missing field detection, and comprehensive documentation generation. Configuration files are automatically created with helpful comments and maintained with complete settings.
- **Tailored Configuration**: Customize Jacked to align with your specific security preferences. Tailor the tool to suit your organization's unique requirements and security policies with well-documented configuration options.
- **Cross-Platform Compatibility**: Jacked seamlessly integrates with major operating systems and supports various package types. It offers flexibility and compatibility to fit into your existing workflow.
- **Diggity Integration**: Enhance your security posture by leveraging Jacked's compatibility with Diggity. This integration provides SBOM (Software Bill of Materials) Container Image and File System support.
- **Integration-Friendly**: Seamlessly integrate Jacked into your CI/CD pipelines and DevOps workflows to automate vulnerability analysis.
- **User-Friendly Interface**: Jacked offers an intuitive command-line interface, making it accessible to both security experts and developers.
- **Flexible Output Formats**: Jacked provides multiple output formats, making it easy to analyze scan results. Choose from options like tabulated summaries, JSON reports, CycloneDX, SPDX, and more.

## What Jacked Includes

Jacked is a comprehensive vulnerability scanning solution that supports a wide range of technologies and provides extensive features:

### 🔍 **Package Ecosystem Support**

Jacked provides comprehensive vulnerability scanning for a wide range of package ecosystems. It includes specialized scanning strategies for the most common ecosystems, while also supporting generic scanning for other package types:

**Ecosystems with Specialized Scanning Strategies:**

- **Operating Systems**: APK (Alpine), DPKG (Debian/Ubuntu), RPM (Red Hat/CentOS/Fedora)
- **Programming Languages**:
  - **JavaScript/Node.js**: NPM packages with semantic versioning
  - **Python**: PyPI packages with PEP 440 version constraints
  - **Java**: Maven artifacts with complex version handling
  - **Go**: Go modules with semantic versioning
  - **Ruby**: RubyGems with version constraints
  - **Dart**: Pub packages for Flutter/Dart applications

**Additional Support:**

- **Advanced matching algorithms** with CPE (Common Platform Enumeration) support
- **Generic Package Scanning**: Supports any package ecosystem through generic vulnerability matching
- **Custom Package Types**: Extensible architecture allows for additional ecosystem support
- **Cross-Platform Compatibility**: Works with packages from various sources and registries
- **Actively Expanding**: We continuously release new specialized scanning strategies for emerging ecosystems
- **Community-Driven**: Users can [request new ecosystem support](https://github.com/carbonetes/jacked/issues) by opening an issue

### 🛡️ **Vulnerability Data Sources**

- **NVD (National Vulnerability Database)**: Comprehensive CVE database
- **GitHub Security Advisories (GHSA)**: Real-time security alerts from GitHub
- **Alpine Security Database**: Alpine Linux specific vulnerabilities
- **Debian Security Tracker**: Debian/Ubuntu package vulnerabilities


With Jacked, you can fortify your software applications against security threats, streamline your vulnerability management process, and deliver software that is secure, compliant, and reliable.

## Installation

## Recommended

### Using Curl (Linux/macOS)

Run the following command to download and install Jacked using Curl:

```bash
curl -sSfL https://raw.githubusercontent.com/carbonetes/jacked/main/install.sh | sh -s -- -d /usr/local/bin
```

**Note**: Use root access with `sudo sh -s -- -d /usr/local/bin` if you encounter a Permission Denied issue, as the `/usr/local/bin` directory requires the necessary permissions to write to the target directory.

### Using Homebrew (Linux/macOS)

First, tap to the jacked repository by running the following command:

```bash
brew tap carbonetes/jacked
```

Then, install Jacked using Homebrew:

```bash
brew install jacked
```

To check if Jacked is installed properly, try running the following command:

```bash
jacked --version
```

### Using Scoop (Windows)

First, add the jacked-bucket by running:

```sh
scoop bucket add diggity https://github.com/carbonetes/jacked-bucket
```

Then, install Jacked using Scoop:

```sh
scoop install jacked
```

Verify that Jacked is installed correctly by running:

```sh
jacked --version
```

**First Run Setup**: When you first run Jacked, it will automatically create a comprehensive configuration file at `~/.jacked.yaml` with detailed documentation and all available settings. You can customize this configuration file to match your specific needs.

# Getting Started

Jacked offers a user-friendly command-line interface, ensuring that it is accessible to both security experts and developers.

## Scanning Docker Images

To scan a Docker image, use the following command:

```bash
jacked <image-name:tag>
```

Replace <image_name> with the name of the Docker image you want to scan.

## Scanning Code Repositories

To analyze a code repository, use the following command:

```bash
jacked --dir <repository-path>
```

## Scanning Tarballs

To scan a tarball, use the following command:

```bash
jacked --tar <tarball-path>
```

## SBOM Analysis

Jacked uses CycloneDX internally as the Software Bill of Materials (SBOM) format for processing and analyzing components. This enables Jacked to provide comprehensive vulnerability analysis with rich component metadata and dependency relationships.

While CycloneDX is used internally for analysis, the scan results can be exported in multiple standard formats including JSON, SPDX, and table formats for integration with your existing toolchain.

## Output formats

Jacked provides flexible options for formatting and presenting scan results, making it easy to tailor the output to your specific needs.

```bash
jacked <target> -o <output-format>
```

You can choose from the following output formats:

- `table`: The default output format, providing a concise columnar summary of the scan results. This format is ideal for a quick overview of vulnerabilities.
- `json`: Get detailed scan results in JSON format, enabling easy integration with other tools and systems for further analysis and automation.
- `spdx-json`: Software Package Data Exchange format in JSON.
- `spdx-xml`: Software Package Data Exchange format in XML.
- `spdx-tag`: Software Package Data Exchange format in tag-value format.
- `snapshot-json`: Snapshot format in JSON for detailed vulnerability data.

Choose the output format that best suits your integration requirements and reporting preferences. Jacked's versatile output options ensure that you can effectively communicate and act on your scan results in a way that aligns with your workflow.

## Vulnerability Severity Threshold

Jacked provides a powerful feature that allows you to set a severity threshold for vulnerabilities, helping you control the actions triggered based on the severity level of identified vulnerabilities. With this feature, you can tailor your security policies to align with your organization's risk tolerance and operational requirements.

### How it Works

In CI mode `--ci`, Jacked can be configured to evaluate the severity of vulnerabilities detected in your images or code repositories. By adding `--fail-criteria` option on scan arguments, you can specify the severity threshold that your organization deems acceptable, such as "low," "medium," or "high."

By defining a severity threshold, you can specify which vulnerabilities should trigger specific actions or policies. For example, you might want to:

- **Fail a CI/CD Pipeline**: Jacked can be integrated into your CI/CD pipeline to halt the pipeline execution if vulnerabilities of a certain severity level (e.g., "low" or higher) are detected. This ensures that only secure code gets deployed.
- **Generate Alerts**: Configure alerts or notifications to be sent to relevant team members when vulnerabilities exceed the specified severity threshold. Stay informed and act swiftly when critical issues arise.

- **Customize Actions**: Define custom actions or policies based on severity levels. For instance, you can automatically open a ticket in your issue tracking system for "high" severity vulnerabilities.

Here's an example of how to use this feature. To trigger a CI pipeline failure if any vulnerabilities are found in the image with a severity of "low" or higher, use the following command:

```bash
jacked <image> --ci --fail-criteria medium
```

<details>
<summary>Sample Evaluation</summary>

<img src="assets/evaluation_sample_alpine_edge.png" style="width: 50%;">

</details>

## Useful Commands and Flags

```
jacked [command] [flag]
```

| SubCommand | Description                                 |
| :--------- | :------------------------------------------ |
| `config`   | Display the current configurations          |
| `db`       | Display the database information            |
| `version`  | Display Build Version Information of Jacked |

### Available Commands and their flags with description:

```
jacked [flag]
```

| Root Flags               | Description                                                                                                   |
| :----------------------- | :------------------------------------------------------------------------------------------------------------ |
| `-d`, `--dir string`     | Read directly from a path on disk (any directory) (e.g. 'jacked -d path/to/directory)'                        |
| `-t`, `--tar string`     | Read a tarball from a path on disk for archives created from docker save (e.g. 'jacked -t path/to/image.tar)' |
| `-o`, `--output string`  | Show scan results in specified format (default "table")                                                       |
| `-q`, `--quiet`          | Suppress all output except for errors                                                                         |
| `-f`, `--file string`    | Save scan result to a file                                                                                    |
| `-c`, `--config string`  | Path to configuration file (default: $HOME/.jacked.yaml)                                                      |
| `--performance string`   | Set performance optimization level (basic, balanced, aggressive, maximum) (default "balanced")                |
| `--ci`                   | Enable CI mode [experimental]                                                                                 |
| `--fail-criteria string` | Set severity threshold for CI failure (e.g. low, medium, high, critical)                                      |
| `--force-db-update`      | Enables immediate implementation of database updates                                                          |
| `--debug`                | Enable debug mode                                                                                             |
| `-v`, `--version`        | Print application version                                                                                     |

```
jacked config [flag]
```

| Config Flags        | Descriptions                                                     |
| :------------------ | :--------------------------------------------------------------- |
| `display`           | Display the content of the configuration file                   |
| `generate [path]`   | Generate a default configuration file with documentation        |
| `path`              | Display the path of the configuration file                      |
| `reset`             | Restore the default configuration file with full documentation  |
| `-h`,`--help`       | Help for configuration commands                                  |

**Configuration Management Examples:**

```bash
# View current configuration
jacked config display

# Reset configuration to documented defaults
jacked config reset

# Generate a new config file in current directory
jacked config generate

# Generate a config file at specific path
jacked config generate /path/to/my-config.yaml

# Show configuration file location
jacked config path
```

```
jacked db [flag]
```

| Database Flags    | Descriptions                        |
| :---------------- | :---------------------------------- |
| `-i`, `--info`    | Print database metadata information |
| `-v`, `--version` | Print database current version      |

```
jacked version [flag] [string]
```

| Version Flags                      | Descriptions                                                   |
| :--------------------------------- | :------------------------------------------------------------- |
| `-f` [string], `--format` [string] | Print application version format (json, text) (default "text") |

## Configuration

Jacked provides comprehensive configuration management with automatic validation and documentation generation. The configuration file is located at `<HOME>/.jacked.yaml` by default.

### Automatic Configuration Management

Jacked automatically:
- **Creates a documented configuration file** when none exists
- **Validates existing configuration** and fills missing fields
- **Regenerates configuration** with complete documentation when incomplete configurations are detected
- **Provides helpful comments** explaining each configuration option

### Configuration File Structure

The configuration file includes comprehensive documentation and all implemented features:

```yaml
# Legacy field for backward compatibility (file size limit in bytes)
maxFileSize: 52428800

# Performance Configuration
# Controls scanning performance and resource usage
performance:
  # Number of concurrent scanners (default: number of CPU cores)
  max_concurrent_scanners: 4
  
  # Enable result caching to speed up repeated scans
  enable_caching: true
  
  # Cache expiration time
  cache_timeout: "1h0m0s"
  
  # Maximum number of cached items
  max_cache_size: 1000
  
  # Database connection settings
  max_db_connections: 10
  max_idle_connections: 5
  connection_timeout: "30s"
  
  # Batch processing settings
  batch_size: 100
  enable_batch_processing: true

# CI/CD Integration Configuration
ci:
  # Criteria for failing CI builds
  fail_criteria:
    # Fail if vulnerabilities of this severity or higher are found
    # Options: "low", "medium", "high", "critical"
    severity: "high"

# Note: This configuration only includes fields that are actually implemented
# in the codebase. Many advanced features shown in documentation may not
# yet be fully implemented.
```

### Configuration Validation

If you have an incomplete configuration file, Jacked will automatically:
1. Detect missing required fields
2. Fill in default values for missing fields
3. Regenerate the configuration file with complete documentation
4. Preserve your custom values while adding missing ones

### Custom Configuration Files

You can specify a custom configuration file path:

```bash
# Use a specific config file
jacked --config=/path/to/custom-config.yaml [command]

# Set via environment variable
export JACKED_CONFIG=/path/to/custom-config.yaml
jacked [command]
```


## Contributing

We welcome contributions to Jacked from the community. We believe that collaboration and contributions from the community are essential to making Jacked even better. Whether it's reporting issues, submitting pull requests, or providing feedback, your input helps improve this project for everyone. Please check our [Contribution Guidelines](https://github.com/carbonetes/jacked/blob/main/CONTRIBUTING.md) for more details on how to get involved.

By contributing to Jacked, you agree to abide by our [Code of Conduct](https://github.com/carbonetes/jacked/blob/main/CODE_OF_CONDUCT.md). We are committed to maintaining an open, inclusive, and respectful community.

If you encounter bugs, have ideas for improvements, or want to request new features, please don't hesitate to open an issue on our [GitHub repository](https://github.com/carbonetes/jacked/issues).

## Contact

If you have any questions, suggestions, or need assistance, you can reach us at [eng@carbonetes.com](mailto:eng@carbonetes.com). Your feedback and engagement are valuable to us.

## License

Jacked is released under the [Apache License 2.0](https://choosealicense.com/licenses/apache-2.0/). You are free to use, modify, and distribute this software in compliance with the terms and conditions of the Apache License 2.0. Please review the full license text for more details.

<footer>
<h4>
  <p align="center">
    Jacked is developed and maintained by <a href="https://carbonetes.com/">Carbonetes</a>. 
  </p>
</h4>
</footer>
