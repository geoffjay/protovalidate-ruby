# frozen_string_literal: true

require_relative "cel_helpers"

module Protovalidate
  module Internal
    # Contains all rule implementations for validation.
    module Rules
      # Base class for all validation rules.
      class Base
        # Validates the given message/value and adds violations to the context.
        #
        # @param context [ValidationContext] The validation context
        # @param message [Google::Protobuf::MessageExts] The message being validated
        def validate(context, message)
          raise NotImplementedError, "Subclasses must implement #validate"
        end

        # Returns true if this rule always passes (tautology).
        # Used for optimization to skip unnecessary rules.
        #
        # @return [Boolean]
        def tautology?
          false
        end
      end

      # Validates a CEL expression at the message level.
      class CelRule < Base
        def initialize(program:, rule:, cel_env:)
          super()
          @program = program
          @rule = rule
          @cel_env = cel_env
        end

        def validate(context, message)
          return if context.done?

          activation = CelHelpers.message_to_activation(message)
          result = @program.evaluate(activation)

          unless result == true || (result.respond_to?(:value) && result.value == true)
            violation = Violation.new(
              constraint_id: @rule.id || "",
              message: @rule.message || "CEL expression evaluated to false"
            )
            context.add(violation)
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("CEL evaluation failed: #{e.message}", cause: e)
        end
      end

      # Validates a CEL expression at the field level.
      class FieldCelRule < Base
        def initialize(field:, program:, rule:, cel_env:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @program = program
          @rule = rule
          @cel_env = cel_env
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)

          # Handle ignore conditions
          return if should_ignore?(value)

          field_elem = build_field_path_element

          context.with_field_path_element(field_elem) do
            activation = CelHelpers.field_to_activation(value, @field)
            result = @program.evaluate(activation)

            unless result == true || (result.respond_to?(:value) && result.value == true)
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: @rule.message || "CEL expression evaluated to false"
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("CEL evaluation failed for field '#{@field.name}': #{e.message}", cause: e)
        end

        private

        def should_ignore?(value)
          case @ignore
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE
            empty_value?(value)
          else
            false
          end
        end

        def empty_value?(value)
          return true if value.nil?

          case value
          when String then value.empty?
          when Numeric then value.zero?
          when TrueClass, FalseClass then false # booleans are never "empty"
          when Array then value.empty?
          when Hash then value.empty?
          else
            # For proto messages, check if it's the default
            if value.respond_to?(:to_h)
              value.to_h.empty?
            else
              false
            end
          end
        end

        def build_field_path_element
          FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: @field.type
          )
        end
      end

      # Validates that a required field is present.
      class RequiredRule < Base
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?
          return if @ignore == :IGNORE_ALWAYS

          value = message.send(@field.name)
          present = field_present?(message, value)

          return if present

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: @field.type
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "required",
              message: "value is required"
            )
            context.add(violation)
          end
        end

        private

        def field_present?(message, value)
          # Check if the field has presence tracking
          if message.respond_to?("has_#{@field.name}?")
            message.send("has_#{@field.name}?")
          else
            !empty_value?(value)
          end
        end

        def empty_value?(value)
          return true if value.nil?

          case value
          when String then value.empty?
          when Numeric then value.zero?
          when TrueClass, FalseClass then false
          when Array then value.empty?
          when Hash then value.empty?
          else
            false
          end
        end
      end

      # Validates that a oneof field is set.
      class OneofRequiredRule < Base
        def initialize(oneof:, constraint:)
          super()
          @oneof = oneof
          @constraint = constraint
        end

        def validate(context, message)
          return if context.done?

          # Check if any field in the oneof is set
          oneof_name = @oneof.name.to_sym
          set_field = message.send(oneof_name) rescue nil

          return if set_field

          violation = Violation.new(
            constraint_id: "oneof.required",
            message: "exactly one field must be set in oneof '#{@oneof.name}'"
          )
          context.add(violation)
        end
      end

      # Validates that an enum value is defined in the enum descriptor.
      class EnumDefinedOnlyRule < Base
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if @ignore == :IGNORE_ALWAYS
          return if @ignore == :IGNORE_IF_UNPOPULATED && value.to_i.zero?

          enum_descriptor = @field.subtype
          return unless enum_descriptor

          # Check if the enum value is defined
          defined = enum_descriptor.lookup_value(value.to_i)
          return if defined

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :enum
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "enum.defined_only",
              message: "value must be a defined enum value"
            )
            violation.field_value = value
            context.add(violation)
          end
        end
      end

      # Validates a nested message field.
      class SubMessageRule < Base
        def initialize(field:, factory:)
          super()
          @field = field
          @factory = factory
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return unless value

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            descriptor = value.class.descriptor
            rules = @factory.get(descriptor)

            rules.each do |rule|
              rule.validate(context, value)
              break if context.done?
            end
          end
        end
      end

      # Validates that an Any message type URL is in an allowed list.
      class AnyInRule < Base
        def initialize(field:, type_urls:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @type_urls = type_urls.to_set
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if value.nil?
          return if @ignore == :IGNORE_ALWAYS

          type_url = value.type_url
          return if @type_urls.include?(type_url)

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "any.in",
              message: "type URL must be one of: #{@type_urls.to_a.join(', ')}"
            )
            violation.field_value = type_url
            context.add(violation)
          end
        end
      end

      # Validates that an Any message type URL is not in a blocked list.
      class AnyNotInRule < Base
        def initialize(field:, type_urls:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @type_urls = type_urls.to_set
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if value.nil?
          return if @ignore == :IGNORE_ALWAYS

          type_url = value.type_url
          return unless @type_urls.include?(type_url)

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "any.not_in",
              message: "type URL must not be one of: #{@type_urls.to_a.join(', ')}"
            )
            violation.field_value = type_url
            context.add(violation)
          end
        end
      end

      # Validates items in a repeated field.
      class RepeatedItemsRule < Base
        def initialize(field:, item_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @item_constraints = item_constraints
          @factory = factory
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          values = message.send(@field.name)
          return if values.nil? || values.empty?
          return if @ignore == :IGNORE_ALWAYS

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: @field.type
          )

          context.with_field_path_element(field_elem) do
            values.each_with_index do |item, index|
              break if context.done?

              index_elem = FieldPathElement.new(
                field_number: @field.number,
                field_name: @field.name,
                field_type: @field.type,
                subscript: index,
                subscript_type: :index
              )

              context.with_field_path_element(index_elem) do
                validate_item(context, item)
              end
            end
          end
        end

        private

        def validate_item(context, item)
          # For message items, recursively validate
          if item.respond_to?(:class) && item.class.respond_to?(:descriptor)
            descriptor = item.class.descriptor
            rules = @factory.get(descriptor)

            rules.each do |rule|
              rule.validate(context, item)
              break if context.done?
            end
          end
        end
      end

      # Validates keys in a map field.
      class MapKeysRule < Base
        def initialize(field:, key_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @key_constraints = key_constraints
          @factory = factory
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          map_value = message.send(@field.name)
          return if map_value.nil? || map_value.empty?
          return if @ignore == :IGNORE_ALWAYS

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            map_value.each_key do |key|
              break if context.done?

              key_elem = build_key_element(key)
              context.with_field_path_element(key_elem) do
                # Key validation would be applied here
              end
            end
          end
        end

        private

        def build_key_element(key)
          subscript_type = case key
                           when String then :string_key
                           when Integer then key >= 0 ? :uint_key : :int_key
                           when TrueClass, FalseClass then :bool_key
                           else :string_key
                           end

          FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message,
            subscript: key,
            subscript_type: subscript_type
          )
        end
      end

      # Validates values in a map field.
      class MapValuesRule < Base
        def initialize(field:, value_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @value_constraints = value_constraints
          @factory = factory
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          map_value = message.send(@field.name)
          return if map_value.nil? || map_value.empty?
          return if @ignore == :IGNORE_ALWAYS

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            map_value.each do |key, value|
              break if context.done?

              key_elem = build_key_element(key)
              context.with_field_path_element(key_elem) do
                validate_value(context, value)
              end
            end
          end
        end

        private

        def validate_value(context, value)
          # For message values, recursively validate
          if value.respond_to?(:class) && value.class.respond_to?(:descriptor)
            descriptor = value.class.descriptor
            rules = @factory.get(descriptor)

            rules.each do |rule|
              rule.validate(context, value)
              break if context.done?
            end
          end
        end

        def build_key_element(key)
          subscript_type = case key
                           when String then :string_key
                           when Integer then key >= 0 ? :uint_key : :int_key
                           when TrueClass, FalseClass then :bool_key
                           else :string_key
                           end

          FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message,
            subscript: key,
            subscript_type: subscript_type
          )
        end
      end
    end
  end
end
