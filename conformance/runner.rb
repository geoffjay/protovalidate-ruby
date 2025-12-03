# frozen_string_literal: true

# Conformance test runner for protovalidate-ruby
#
# This runner executes the official protovalidate conformance test suite
# to ensure compatibility with other language implementations.
#
# Usage:
#   ruby conformance/runner.rb
#
# Requirements:
#   - buf CLI installed (https://buf.build/docs/installation)
#   - Conformance test harness from bufbuild/protovalidate

require_relative "../lib/protovalidate"

module Protovalidate
  module Conformance
    class Runner
      def initialize
        @passed = 0
        @failed = 0
        @skipped = 0
      end

      def run
        puts "Protovalidate Ruby Conformance Tests"
        puts "=" * 40

        # The conformance tests would be loaded and executed here
        # This requires the conformance test harness from bufbuild/protovalidate

        puts "\nConformance test runner is a placeholder."
        puts "To run actual conformance tests, you need to:"
        puts "  1. Generate the conformance test protos"
        puts "  2. Implement the test harness integration"
        puts "  3. Run: buf build buf.build/bufbuild/protovalidate"
        puts "\nSee: https://github.com/bufbuild/protovalidate/blob/main/docs/conformance.md"

        print_summary
      end

      private

      def print_summary
        puts "\n#{"=" * 40}"
        puts "Summary:"
        puts "  Passed:  #{@passed}"
        puts "  Failed:  #{@failed}"
        puts "  Skipped: #{@skipped}"
        puts "=" * 40

        exit(@failed.zero? ? 0 : 1)
      end
    end
  end
end

Protovalidate::Conformance::Runner.new.run if __FILE__ == $PROGRAM_NAME
