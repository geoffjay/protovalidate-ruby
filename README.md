[![The Buf logo](.github/buf-logo.svg)][buf]

# protovalidate-ruby

[Protovalidate][protovalidate] is the semantic validation library for Protobuf. It provides standard annotations to
validate common rules on messages and fields, as well as the ability to use [CEL][cel] to write custom rules. It's the
next generation of [protoc-gen-validate][protoc-gen-validate].

With Protovalidate, you can annotate your Protobuf messages with both standard and custom validation rules:

```protobuf
syntax = "proto3";

package acme.user.v1;

import "buf/validate/validate.proto";

message User {
  string id = 1 [(buf.validate.field).string.uuid = true];
  uint32 age = 2 [(buf.validate.field).uint32.lte = 150]; // We can only hope.
  string email = 3 [(buf.validate.field).string.email = true];
  string first_name = 4 [(buf.validate.field).string.max_len = 64];
  string last_name = 5 [(buf.validate.field).string.max_len = 64];

  option (buf.validate.message).cel = {
    id: "first_name_requires_last_name"
    message: "last_name must be present if first_name is present"
    expression: "!has(this.first_name) || has(this.last_name)"
  };
}
```

Once you've added `protovalidate` to your project, validation is idiomatic Ruby:

```ruby
begin
  Protovalidate.validate(message)
rescue Protovalidate::ValidationError => e
  # Handle failure.
end
```

## Installation

Add the gem to your Gemfile:

```ruby
gem 'protovalidate'
```

Then run:

```shell
bundle install
```

Or install it directly:

```shell
gem install protovalidate
```

## Documentation

Comprehensive documentation for Protovalidate is available at [protovalidate.com][protovalidate].

Highlights include:

- The [developer quickstart][quickstart]
- A [migration guide for protoc-gen-validate][migration-guide] users

## Development

### Running Tests

```shell
bundle install
bundle exec rake test
```

### Running Conformance Tests

To run the official protovalidate conformance test suite, you need the `protovalidate-conformance` tool:

```shell
# Install the conformance tool (requires Go)
go install github.com/bufbuild/protovalidate/tools/protovalidate-conformance@latest

# Run conformance tests
bundle exec rake conformance

# Run with verbose output
bundle exec rake conformance:verbose
```

### Regenerating Protobuf Files

```shell
# Requires buf CLI (https://buf.build/docs/installation)
bundle exec rake proto
```

## Additional languages and repositories

Protovalidate isn't just for Ruby! You might be interested in sibling repositories for other languages:

- [`protovalidate-go`][pv-go] (Go)
- [`protovalidate-java`][pv-java] (Java)
- [`protovalidate-python`][pv-python] (Python)
- [`protovalidate-cc`][pv-cc] (C++)
- [`protovalidate-es`][pv-es] (TypeScript and JavaScript)

Additionally, [protovalidate's core repository](https://github.com/bufbuild/protovalidate) provides:

- [Protovalidate's Protobuf API][validate-proto]
- [Conformance testing utilities][conformance] for acceptance testing of `protovalidate` implementations

## Contributing

We genuinely appreciate any help! If you'd like to contribute, check out these resources:

- [Contributing Guidelines][contributing]: Guidelines to make your contribution process straightforward and meaningful
- [Conformance testing utilities](https://github.com/bufbuild/protovalidate/tree/main/docs/conformance.md): Utilities providing acceptance testing of `protovalidate` implementations

## Legal

Offered under the [Apache 2 license][license].

[buf]: https://buf.build
[cel]: https://cel.dev
[pv-go]: https://github.com/bufbuild/protovalidate-go
[pv-java]: https://github.com/bufbuild/protovalidate-java
[pv-python]: https://github.com/bufbuild/protovalidate-python
[pv-cc]: https://github.com/bufbuild/protovalidate-cc
[pv-es]: https://github.com/bufbuild/protovalidate-es
[license]: LICENSE
[contributing]: .github/CONTRIBUTING.md
[protoc-gen-validate]: https://github.com/bufbuild/protoc-gen-validate
[protovalidate]: https://protovalidate.com/
[quickstart]: https://protovalidate.com/quickstart/
[migration-guide]: https://protovalidate.com/migration-guides/migrate-from-protoc-gen-validate/
[validate-proto]: https://buf.build/bufbuild/protovalidate/docs/main:buf.validate
[conformance]: https://github.com/bufbuild/protovalidate/blob/main/docs/conformance.md
