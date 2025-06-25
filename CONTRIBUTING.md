# Contributing to Protect.php FFI

Thank you for your interest in contributing to Protect.php FFI! This document provides guidelines and information for contributors.

## Reporting Issues

### Bug Reports and Feature Requests

Please use the GitHub issue tracker to report bugs, suggest features, or documentation improvements.

[When filing an issue](https://github.com/cipherstash/protectphp-ffi/issues/new/choose), please check [existing open](https://github.com/cipherstash/protectphp-ffi/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc), or [recently closed](https://github.com/cipherstash/protectphp-ffi/issues?q=is%3Aissue+sort%3Aupdated-desc+is%3Aclosed), issues to make sure somebody else hasn't already reported the issue.

When reporting issues, please include:

- PHP version and platform information
- Steps to reproduce the issue
- Expected vs actual behavior
- Any relevant error messages or logs
- Minimal code example demonstrating the problem

### Security Issues

If you discover a potential security issue in this project, we ask that you contact us at security@cipherstash.com.

Please do not create a public GitHub issue for security vulnerabilities.

## Development Setup

### Requirements

- [Rust](https://rustup.rs) (automatically managed via `rust-toolchain.toml`)
- [PHP 8.1+](https://www.php.net/downloads) with FFI extension (included in most distributions)
- [Composer](https://getcomposer.org/download/)

### Initial Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/cipherstash/protectphp-ffi.git

cd protectphp-ffi

composer install
```

### Building Native Libraries

Build the native library when modifying Rust code:

```bash
# Builds native library for your current platform (not committed to this repository)
composer build
```

Local builds take precedence over prebuilt libraries. Remove the `target/` directory to use prebuilt libraries again.

## Development Workflow

### Code Quality Standards

Ensure your code passes all quality checks before committing changes:

#### PHP Code Quality

```bash
# Format code
composer format

# Run static analysis
composer stan
```

#### Rust Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy --lib -- -D warnings
```

### Testing

Run the test suite to verify your changes:

#### Rust Tests

```bash
# Rust unit tests
cargo test --lib --bins --jobs 2
```

#### PHP Tests

```bash
# PHP unit tests
composer test:unit

# PHP integration tests (requires CipherStash credentials in .env file)
composer test:integration
```

### Commit Message Guidelines

This project follows [Conventional Commits](https://www.conventionalcommits.org) format, for example:

```
feat(client): add `createSearchTerms()` method for searchable encryption
```

```
feat(exceptions): add `failedToCreateSearchTerms()` exception factory method
```

```
fix(loader): normalize `aarch64` architecture to `arm64` for consistency
```

```
fix(client): prevent memory leaks in `executeFFIOperation()` error handling
```

```
perf(rust): optimize JSON serialization in `create_search_terms()` FFI function
```

```
refactor(loader): consolidate platform detection in `detectPlatform()` method
```

```
docs(readme): add searchable encryption examples with EQL integration
```

```
docs(client): document FFI pointer lifecycle and memory management
```

```
test(integration): add `createSearchTerms()` validation
```

```
test(unit): verify FFI string pointer allocation and cleanup
```

```
build(platforms): update all native libraries
```

```
chore(composer): bump minimum PHP version requirement from 8.1 to 8.2
```

```
ci(workflows): add ARM64 Ubuntu runners
```

```
style(phpstan): fix `FFI\CData` type annotations in `Client` class
```

## Pull Request Process

1. **Fork the repository** and create your feature branch from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Make your changes** to implement your feature or fix
3. **Add tests** for any new functionality or bug fixes
4. **Update documentation** as needed (README, code comments, etc.)
5. **Run quality checks and tests** to validate your changes
6. **Submit a pull request** with conventional commit messages and a clear description

### Pull Request Requirements

- Code must be properly formatted and pass static analysis
- New features must include appropriate tests
- All tests must pass
- Breaking changes must be clearly documented
- Commit messages should follow [Conventional Commits](https://www.conventionalcommits.org/) format

## Continuous Integration

Pull requests are automatically tested across all [supported platforms and PHP versions](README.md#requirements) to ensure compatibility before merging.

The CI/CD pipeline:

1. **Detects changes** to determine which components need testing
2. **Performs code quality checks** (formatting, linting, static analysis)
3. **Runs Rust unit tests** when Rust code changes
4. **Builds native libraries** for all platforms when Rust code changes
5. **Runs comprehensive PHP test suites** across all platform/PHP combinations
6. **Commits updated native libraries** when Rust changes pass all tests

Only pull requests that pass all checks will be merged.

## Project Information

### Versioning and Releases

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Version numbers are structured as `MAJOR.MINOR.PATCH`:

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality in a backwards compatible manner
- **PATCH**: Backwards compatible bug fixes

The [CHANGELOG](CHANGELOG.md) file will soon be automatically generated based on [Conventional Commits](https://www.conventionalcommits.org/). Please avoid editing it manually.

### Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/). For more information see the [Code of Conduct FAQ](CODE_OF_CONDUCT.md) or contact support@cipherstash.com with any questions or comments.

### License

By contributing to Protect.php FFI, you agree that your contributions will be licensed under the same license as the project. See the [LICENSE](LICENSE.md) file for our project's licensing.
