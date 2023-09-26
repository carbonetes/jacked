# Development Setup Guide

This guide will help you set up Jacked for development on your local machine. By following these steps, you can contribute to the project and work on improvements, bug fixes, and new features.

## Prerequisites

Before you begin, make sure you have the following prerequisites installed on your system:

- **Go:** Jacked is written in Go, so you'll need to have [Go installed](https://golang.org/doc/install) on your system.

## Cloning the Repository

First, you'll need to clone the Jacked repository to your local machine. Open a terminal and run the following command:

```bash
git clone https://github.com/carbonetes/jacked.git
```

## Installing Dependencies
Jacked relies on various libraries and dependencies. You can use Go modules to manage these dependencies. Navigate to the cloned Jacked directory and run:
```bash
cd jacked
go mod download
```
This command will download and install the required dependencies.

## Building Jacked
To build Jacked, you can use the following command:
```bash
go build -o jacked
```
This command will compile Jacked and create an executable binary named jacked. You can use this binary to run Jacked on your system.

## Running Jacked
You can run Jacked locally with the following command:
```bash
./jacked <target>
```
Replace <target> with the image, code repository, or tarball you want to scan. Jacked will analyze the target for vulnerabilities based on your configuration.

## Development Workflow
1. Make your code changes following the project's coding standards and guidelines.
2. Create a new branch for your changes:
```bash
git checkout -b feature-or-fix-name
```
3. Commit your changes with descriptive commit messages:
```bash
git commit -m "Add your descriptive message here"
```
4. Push your branch to your fork on GitHub:
```bash
git push origin feature-or-fix-name
```
5. Create a pull request (PR) from your branch to the main Jacked repository. Be sure to include a clear description of your changes in the PR.

## Testing
Jacked has a suite of tests to ensure its functionality. You can run the tests using the following command:
```bash
go test ./...
```
Make sure all tests pass before submitting a pull request.

## Code Style
Please adhere to the project's coding standards and style guidelines to maintain consistency throughout the codebase. We recommend following [Go's official coding style and conventions](https://google.github.io/styleguide/go/).

## Licensing
By contributing to Jacked, you agree to license your contributions under the terms of the [Apache 2.0](https://choosealicense.com/licenses/apache-2.0/). All contributions will be subject to this license.

## Contact
If you have any questions, need assistance, or want to discuss your contributions, please don't hesitate to contact us at [eng@carbonetes.com](mailto:eng@carbonetes.com).

Happy coding!