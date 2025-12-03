# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require "rubocop/rake_task"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb", "spec/**/*_spec.rb"]
end

RuboCop::RakeTask.new

desc "Generate protobuf files from buf.build/bufbuild/protovalidate"
task :proto do
  # Requires buf CLI to be installed
  # See: https://buf.build/docs/installation
  sh "buf generate"
end

desc "Run conformance tests using protovalidate-conformance tool"
task :conformance do
  # Requires protovalidate-conformance tool to be installed
  # See: https://github.com/bufbuild/protovalidate
  expected_failures = File.exist?("conformance/expected_failures.yaml") ? "--expected_failures=conformance/expected_failures.yaml" : ""
  sh "protovalidate-conformance #{expected_failures} -- bundle exec ruby conformance/runner.rb"
end

desc "Run conformance tests (verbose output)"
task "conformance:verbose" do
  expected_failures = File.exist?("conformance/expected_failures.yaml") ? "--expected_failures=conformance/expected_failures.yaml" : ""
  sh "protovalidate-conformance --verbose #{expected_failures} -- bundle exec ruby conformance/runner.rb"
end

task default: %i[test rubocop]
