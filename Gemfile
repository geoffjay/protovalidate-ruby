# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in protovalidate.gemspec
gemspec

# Use local cel-ruby if available
if File.exist?(File.expand_path("contrib/cel-ruby", __dir__))
  gem "cel", path: "contrib/cel-ruby"
end

group :development do
  gem "minitest", "~> 5.0"
  gem "rake", "~> 13.0"
  gem "rubocop", "~> 1.21"
end

group :test do
  gem "minitest-reporters", "~> 1.6"
  gem "simplecov", require: false
end
