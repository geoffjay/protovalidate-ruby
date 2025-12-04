#!/usr/bin/env ruby
# frozen_string_literal: true

# Conformance test runner for protovalidate-ruby
#
# This runner executes the official protovalidate conformance test suite
# to ensure compatibility with other language implementations.
#
# Protocol:
#   - Reads binary TestConformanceRequest from stdin
#   - Processes each test case by unpacking Any messages and validating
#   - Writes binary TestConformanceResponse to stdout
#
# Usage:
#   protovalidate-conformance ruby conformance/runner.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../gen", __dir__)
$LOAD_PATH.unshift File.expand_path("../contrib/cel-ruby/lib", __dir__)

require "google/protobuf"
require "google/protobuf/any_pb"
require "google/protobuf/descriptor_pb"

# Load all generated conformance case protos
Dir[File.expand_path("../gen/buf/validate/conformance/**/*_pb.rb", __dir__)].each do |file|
  require file
end

require "protovalidate"

module Protovalidate
  module Conformance
    class Runner
      def initialize
        @validator = Protovalidate::Validator.new
      end

      # Main entry point - reads request from stdin, writes response to stdout
      def run
        # Read binary request from stdin
        request_data = $stdin.binmode.read
        request = Buf::Validate::Conformance::Harness::TestConformanceRequest.decode(request_data)

        # Process the request
        response = process_request(request)

        # Write binary response to stdout
        $stdout.binmode.write(response.to_proto)
        $stdout.flush
      end

      private

      # Process a conformance test request
      #
      # @param request [Buf::Validate::Conformance::Harness::TestConformanceRequest]
      # @return [Buf::Validate::Conformance::Harness::TestConformanceResponse]
      def process_request(request)
        # Register file descriptors from the request
        register_file_descriptors(request.fdset)

        # Process each test case
        results = {}
        request.cases.each do |name, any_case|
          results[name] = run_test_case(name, any_case)
        end

        Buf::Validate::Conformance::Harness::TestConformanceResponse.new(results: results)
      end

      # Register file descriptors in the descriptor pool
      #
      # @param fdset [Google::Protobuf::FileDescriptorSet]
      def register_file_descriptors(fdset)
        return if fdset.nil? || fdset.file.empty?

        pool = Google::Protobuf::DescriptorPool.generated_pool

        # Try to add each file descriptor
        fdset.file.each do |file_proto|
          # Skip if already registered
          next if pool.lookup(file_proto.name)

          begin
            # Serialize the file descriptor and add it to the pool
            pool.add_serialized_file(file_proto.to_proto)
          rescue Google::Protobuf::Error
            # File may already exist or have dependency issues
            # Continue with other files
          end
        end
      end

      # Run a single test case
      #
      # @param name [String] Test case name
      # @param any_case [Google::Protobuf::Any] The test case wrapped in Any
      # @return [Buf::Validate::Conformance::Harness::TestResult]
      def run_test_case(name, any_case)
        result = Buf::Validate::Conformance::Harness::TestResult.new

        begin
          # Unpack the Any message to get the actual test case
          message = unpack_any(any_case)

          if message.nil?
            result.unexpected_error = "Failed to unpack Any message for case: #{name}"
            return result
          end

          # Validate the message
          violations = @validator.collect_violations(message)

          if violations.empty?
            result.success = true
          else
            result.validation_error = violations_to_proto(violations)
          end
        rescue Protovalidate::CompilationError => e
          result.compilation_error = e.message
        rescue Protovalidate::RuntimeError => e
          result.runtime_error = e.message
        rescue StandardError => e
          result.unexpected_error = "#{e.class}: #{e.message}"
        end

        result
      end

      # Unpack an Any message into its concrete type
      #
      # @param any [Google::Protobuf::Any] The Any message to unpack
      # @return [Google::Protobuf::MessageExts, nil] The unpacked message or nil
      def unpack_any(any)
        return nil if any.nil? || any.type_url.empty?

        # Extract the type name from the type URL
        # Format: type.googleapis.com/full.type.name or /full.type.name
        type_name = any.type_url.split("/").last

        # Look up the message descriptor
        pool = Google::Protobuf::DescriptorPool.generated_pool
        descriptor = pool.lookup(type_name)

        return nil if descriptor.nil?

        # Create a new message instance and decode the value
        message_class = descriptor.msgclass
        message_class.decode(any.value)
      end

      # Convert violations to protobuf format
      #
      # @param violations [Array<Protovalidate::Violation>]
      # @return [Buf::Validate::Violations]
      def violations_to_proto(violations)
        proto_violations = violations.map do |v|
          Buf::Validate::Violation.new(
            field: field_path_to_proto(v.field_path),
            rule: rule_path_to_proto(v.rule_path),
            rule_id: v.constraint_id || "",
            message: v.message || "",
            for_key: v.for_key || false
          )
        end

        Buf::Validate::Violations.new(violations: proto_violations)
      end

      # Convert a FieldPath to protobuf format
      #
      # @param field_path [Protovalidate::FieldPath, nil]
      # @return [Buf::Validate::FieldPath, nil]
      def field_path_to_proto(field_path)
        return nil if field_path.nil?

        elements = field_path.elements.map do |elem|
          proto_elem = Buf::Validate::FieldPathElement.new(
            field_number: elem.field_number,
            field_name: elem.field_name,
            field_type: field_type_to_proto(elem.field_type)
          )

          # Set key_type and value_type for map fields
          if elem.key_type
            proto_elem.key_type = field_type_to_proto(elem.key_type)
          end
          if elem.value_type
            proto_elem.value_type = field_type_to_proto(elem.value_type)
          end

          # Set subscript if present
          case elem.subscript_type
          when :index
            proto_elem.index = elem.subscript.to_i
          when :bool_key
            proto_elem.bool_key = elem.subscript
          when :int_key
            proto_elem.int_key = elem.subscript.to_i
          when :uint_key
            proto_elem.uint_key = elem.subscript.to_i
          when :string_key
            proto_elem.string_key = elem.subscript.to_s
          end

          proto_elem
        end

        Buf::Validate::FieldPath.new(elements: elements)
      end

      # Convert rule path elements to protobuf format
      #
      # @param rule_path [Array<Protovalidate::FieldPathElement>]
      # @return [Buf::Validate::FieldPath, nil]
      def rule_path_to_proto(rule_path)
        return nil if rule_path.nil? || rule_path.empty?

        elements = rule_path.map do |elem|
          Buf::Validate::FieldPathElement.new(
            field_number: elem.field_number,
            field_name: elem.field_name,
            field_type: field_type_to_proto(elem.field_type)
          )
        end

        Buf::Validate::FieldPath.new(elements: elements)
      end

      # Convert Ruby field type symbol to protobuf enum
      #
      # @param field_type [Symbol]
      # @return [Symbol]
      def field_type_to_proto(field_type)
        type_map = {
          double: :TYPE_DOUBLE,
          float: :TYPE_FLOAT,
          int64: :TYPE_INT64,
          uint64: :TYPE_UINT64,
          int32: :TYPE_INT32,
          fixed64: :TYPE_FIXED64,
          fixed32: :TYPE_FIXED32,
          bool: :TYPE_BOOL,
          string: :TYPE_STRING,
          group: :TYPE_GROUP,
          message: :TYPE_MESSAGE,
          bytes: :TYPE_BYTES,
          uint32: :TYPE_UINT32,
          enum: :TYPE_ENUM,
          sfixed32: :TYPE_SFIXED32,
          sfixed64: :TYPE_SFIXED64,
          sint32: :TYPE_SINT32,
          sint64: :TYPE_SINT64
        }

        type_map[field_type] || :TYPE_MESSAGE
      end
    end
  end
end

# Run the conformance harness
Protovalidate::Conformance::Runner.new.run if __FILE__ == $PROGRAM_NAME
