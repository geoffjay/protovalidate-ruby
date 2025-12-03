# frozen_string_literal: true

require_relative "lib/protovalidate/version"

Gem::Specification.new do |spec|
  spec.name = "protovalidate"
  spec.version = Protovalidate::VERSION
  spec.authors = ["Buf Technologies"]
  spec.email = ["dev@buf.build"]

  spec.summary = "Protocol Buffer validation for Ruby"
  spec.description = <<~DESC
    Protovalidate is the semantic validation library for Protocol Buffers.
    It provides standard annotations to validate common rules on messages and
    fields, as well as the ability to use CEL to write custom rules.
  DESC
  spec.homepage = "https://github.com/bufbuild/protovalidate-ruby"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = "https://protovalidate.com/"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ contrib/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "cel", "~> 0.4"
  spec.add_dependency "google-protobuf", ">= 4.0"

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.21"
end
