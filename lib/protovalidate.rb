# frozen_string_literal: true

require_relative "protovalidate/version"
require_relative "protovalidate/error"
require_relative "protovalidate/violation"
require_relative "protovalidate/validator"

module Protovalidate
  class << self
    # Validates a protobuf message against its validation rules.
    #
    # @param message [Google::Protobuf::MessageExts] The protobuf message to validate
    # @param fail_fast [Boolean] If true, stop validation after the first violation
    # @return [void]
    # @raise [ValidationError] If the message has validation violations
    #
    # @example
    #   begin
    #     Protovalidate.validate(message)
    #   rescue Protovalidate::ValidationError => e
    #     puts e.violations
    #   end
    def validate(message, fail_fast: false)
      validator.validate(message, fail_fast: fail_fast)
    end

    # Validates a protobuf message and returns violations without raising.
    #
    # @param message [Google::Protobuf::MessageExts] The protobuf message to validate
    # @param fail_fast [Boolean] If true, stop validation after the first violation
    # @return [Array<Violation>] List of violations (empty if valid)
    #
    # @example
    #   violations = Protovalidate.collect_violations(message)
    #   if violations.any?
    #     violations.each { |v| puts v.message }
    #   end
    def collect_violations(message, fail_fast: false)
      validator.collect_violations(message, fail_fast: fail_fast)
    end

    private

    def validator
      @validator ||= Validator.new
    end
  end
end
