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
  sh "buf generate buf.build/bufbuild/protovalidate --path buf/validate"
end

desc "Run conformance tests"
task :conformance do
  ruby "conformance/runner.rb"
end

task default: %i[test rubocop]
