# frozen_string_literal: true

module Protovalidate
  # Base error class for all protovalidate errors.
  class Error < StandardError; end

  # Raised when rule compilation fails.
  # This typically indicates a malformed CEL expression or invalid rule configuration.
  class CompilationError < Error
    attr_reader :cause

    def initialize(message, cause: nil)
      @cause = cause
      super(message)
    end
  end

  # Raised when validation fails.
  # Contains a list of all violations found during validation.
  class ValidationError < Error
    # @return [Array<Violation>] The list of validation violations
    attr_reader :violations

    # @param message [Google::Protobuf::MessageExts] The message that failed validation
    # @param violations [Array<Violation>] The violations found
    def initialize(message, violations)
      @violations = violations
      super("invalid #{message.class.descriptor.name}: #{violations.size} violation(s)")
    end

    # Converts violations to a protobuf Violations message.
    #
    # @return [Buf::Validate::Violations] The violations as a protobuf message
    def to_proto
      require_relative "../gen/buf/validate/validate_pb"
      Buf::Validate::Violations.new(violations: violations.map(&:to_proto))
    end
  end

  # Raised when a runtime error occurs during CEL expression evaluation.
  class RuntimeError < Error
    attr_reader :cause

    def initialize(message, cause: nil)
      @cause = cause
      super(message)
    end
  end
end
