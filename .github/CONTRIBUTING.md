# Contributing to protovalidate-ruby

We welcome contributions to protovalidate-ruby! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies:
   ```bash
   bundle install
   ```
4. Run the tests:
   ```bash
   bundle exec rake test
   ```

## Development Setup

### Prerequisites

- Ruby 3.1 or later
- Bundler
- [buf CLI](https://buf.build/docs/installation) (for proto generation)

### Installing Dependencies

```bash
bundle install
```

### Running Tests

```bash
# Run all tests
bundle exec rake test

# Run a specific test file
bundle exec ruby -Ilib:test test/protovalidate_test.rb
```

### Code Style

We use RuboCop for code style enforcement:

```bash
bundle exec rubocop
```

To auto-fix issues:

```bash
bundle exec rubocop -a
```

### Generating Protobuf Files

To regenerate the protobuf files from buf.build/bufbuild/protovalidate:

```bash
bundle exec rake proto
```

This requires the buf CLI to be installed.

## Making Changes

1. Create a feature branch from `main`
2. Make your changes
3. Add or update tests as needed
4. Ensure all tests pass
5. Ensure RuboCop passes
6. Commit your changes with a clear message
7. Push to your fork
8. Open a Pull Request

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation as needed
- Follow the existing code style
- Write clear commit messages

## Conformance Tests

protovalidate uses a shared conformance test suite across all language implementations. To run conformance tests:

```bash
bundle exec rake conformance
```

For more information about conformance testing, see the [protovalidate conformance documentation](https://github.com/bufbuild/protovalidate/blob/main/docs/conformance.md).

## Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub with:

- A clear description of the issue
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Ruby version and platform information

## Code of Conduct

Please note that this project follows Buf's code of conduct. Be respectful and inclusive in all interactions.

## License

By contributing to protovalidate-ruby, you agree that your contributions will be licensed under the Apache 2.0 License.
