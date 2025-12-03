# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - TBD

### Added

- Initial implementation of protovalidate for Ruby
- Core `Validator` class for validating protobuf messages
- Support for message-level CEL expressions
- Support for field-level CEL expressions
- Support for oneof constraints
- String validation rules (min_len, max_len, pattern, email, uri, hostname, ip, uuid)
- Numeric validation rules (gt, gte, lt, lte, const, in, not_in)
- Bytes validation rules (min_len, max_len, len)
- Enum validation rules (defined_only, in, not_in)
- Bool validation rules (const)
- Repeated field validation rules (min_items, max_items, unique, items)
- Map field validation rules (min_pairs, max_pairs, keys, values)
- Any message validation rules (in, not_in type URLs)
- `ValidationError` exception with detailed violation information
- `CompilationError` for rule compilation failures
- `RuntimeError` for CEL evaluation failures
- Field path tracking for precise error locations
- Fail-fast mode for early termination
- Global singleton validator for convenience
- Thread-safe rule caching

### Dependencies

- `cel` ~> 0.4 - CEL expression evaluation
- `google-protobuf` >= 4.0 - Protocol Buffer runtime

[Unreleased]: https://github.com/bufbuild/protovalidate-ruby/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bufbuild/protovalidate-ruby/releases/tag/v0.1.0
