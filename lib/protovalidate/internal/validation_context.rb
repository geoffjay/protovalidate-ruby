# frozen_string_literal: true

module Protovalidate
  module Internal
    # Maintains state during validation of a message.
    # Tracks violations and supports fail-fast mode.
    class ValidationContext
      # @return [Array<Violation>] The collected violations
      attr_reader :violations

      # @return [Boolean] Whether to stop on first violation
      attr_reader :fail_fast

      def initialize(fail_fast: false)
        @violations = []
        @fail_fast = fail_fast
        @field_path_elements = []
        @rule_path_elements = []
      end

      # Adds a violation to the context.
      #
      # @param violation [Violation] The violation to add
      def add(violation)
        # Apply current field path
        unless @field_path_elements.empty?
          violation.field_path ||= FieldPath.new
          @field_path_elements.reverse_each do |elem|
            violation.field_path.elements.unshift(elem)
          end
        end

        # Apply current rule path
        @rule_path_elements.reverse_each do |elem|
          violation.rule_path.unshift(elem)
        end

        @violations << violation
      end

      # Merges violations from another context.
      #
      # @param other [ValidationContext] The context to merge from
      def merge(other)
        @violations.concat(other.violations)
      end

      # Returns true if validation should stop.
      #
      # @return [Boolean]
      def done?
        fail_fast && @violations.any?
      end

      # Returns true if any violations have been recorded.
      #
      # @return [Boolean]
      def has_errors?
        @violations.any?
      end

      # Creates a sub-context for nested validation.
      #
      # @return [ValidationContext]
      def sub_context
        ctx = ValidationContext.new(fail_fast: fail_fast)
        ctx
      end

      # Adds a field path element to the current path stack.
      #
      # @param element [FieldPathElement] The element to add
      # @yield Executes the block with the element on the stack
      def with_field_path_element(element)
        @field_path_elements.push(element)
        yield
      ensure
        @field_path_elements.pop
      end

      # Adds a rule path element to the current path stack.
      #
      # @param element [FieldPathElement] The element to add
      # @yield Executes the block with the element on the stack
      def with_rule_path_element(element)
        @rule_path_elements.push(element)
        yield
      ensure
        @rule_path_elements.pop
      end

      # Finalizes violation paths by reversing the breadcrumb trail.
      def finalize_violations
        @violations.each do |violation|
          violation.field_path&.elements&.reverse! if violation.field_path
          violation.rule_path.reverse!
        end
      end
    end
  end
end
