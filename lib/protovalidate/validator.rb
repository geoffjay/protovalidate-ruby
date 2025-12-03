# frozen_string_literal: true

require "cel"
require_relative "internal/rule_factory"
require_relative "internal/validation_context"

module Protovalidate
  # Main validator class for validating protobuf messages.
  #
  # The Validator compiles and caches validation rules for each message type
  # it encounters. It uses CEL (Common Expression Language) to evaluate
  # custom validation expressions.
  #
  # @example Creating a validator
  #   validator = Protovalidate::Validator.new
  #   validator.validate(message)
  #
  # @example With fail-fast mode
  #   validator.validate(message, fail_fast: true)
  class Validator
    # Creates a new Validator instance.
    #
    # @param fail_fast [Boolean] Default fail_fast mode for validations
    def initialize(fail_fast: false)
      @default_fail_fast = fail_fast
      @rule_factory = Internal::RuleFactory.new
    end

    # Validates a protobuf message against its validation rules.
    #
    # @param message [Google::Protobuf::MessageExts] The protobuf message to validate
    # @param fail_fast [Boolean] If true, stop validation after the first violation
    # @return [void]
    # @raise [ValidationError] If the message has validation violations
    def validate(message, fail_fast: @default_fail_fast)
      violations = collect_violations(message, fail_fast: fail_fast)
      raise ValidationError.new(message, violations) if violations.any?
    end

    # Validates a protobuf message and returns violations without raising.
    #
    # @param message [Google::Protobuf::MessageExts] The protobuf message to validate
    # @param fail_fast [Boolean] If true, stop validation after the first violation
    # @return [Array<Violation>] List of violations (empty if valid)
    def collect_violations(message, fail_fast: @default_fail_fast)
      return [] if message.nil?

      descriptor = message.class.descriptor
      return [] unless descriptor

      rules = @rule_factory.get(descriptor)
      return [] if rules.empty?

      context = Internal::ValidationContext.new(fail_fast: fail_fast)

      rules.each do |rule|
        rule.validate(context, message)
        break if context.done?
      end

      context.finalize_violations
      context.violations
    end
  end
end
