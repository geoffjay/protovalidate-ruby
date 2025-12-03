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
          # Handle both symbol and integer enum values from protobuf
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            empty_value?(value)
          else
            false
          end
        end

        def normalize_ignore(ignore)
          return ignore if ignore.is_a?(Symbol)

          case ignore
          when 0 then :IGNORE_UNSPECIFIED
          when 1 then :IGNORE_IF_ZERO_VALUE
          when 3 then :IGNORE_ALWAYS
          else :IGNORE_UNSPECIFIED
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
          set_field = begin
            message.send(oneof_name)
          rescue StandardError
            nil
          end

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

          enum_descriptor = @field.subtype
          return unless enum_descriptor

          # Get the numeric value - symbols are defined, integers may not be
          numeric_value = if value.is_a?(Symbol)
                            # lookup_name returns the integer value directly
                            enum_descriptor.lookup_name(value) || 0
                          else
                            value.to_i
                          end

          return if @ignore == :IGNORE_IF_UNPOPULATED && numeric_value.zero?

          # Check if the enum value is defined
          defined = enum_descriptor.lookup_value(numeric_value)
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

      # Validates that an enum value equals a constant.
      class EnumConstRule < Base
        def initialize(field:, const_value:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @const_value = const_value
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if @ignore == :IGNORE_ALWAYS

          numeric_value = enum_to_int(value, @field.subtype)
          return if @ignore == :IGNORE_IF_UNPOPULATED && numeric_value.zero?

          return if numeric_value == @const_value

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :enum
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "enum.const",
              message: "value must equal #{@const_value}"
            )
            violation.field_value = value
            context.add(violation)
          end
        end

        private

        def enum_to_int(value, enum_descriptor)
          if value.is_a?(Symbol)
            # lookup_name returns the integer value directly
            enum_descriptor&.lookup_name(value) || 0
          else
            value.to_i
          end
        end
      end

      # Validates that an enum value is in a list.
      class EnumInRule < Base
        def initialize(field:, in_list:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @in_list = in_list
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if @ignore == :IGNORE_ALWAYS

          numeric_value = enum_to_int(value, @field.subtype)
          return if @ignore == :IGNORE_IF_UNPOPULATED && numeric_value.zero?

          return if @in_list.include?(numeric_value)

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :enum
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "enum.in",
              message: "value must be in [#{@in_list.join(', ')}]"
            )
            violation.field_value = value
            context.add(violation)
          end
        end

        private

        def enum_to_int(value, enum_descriptor)
          if value.is_a?(Symbol)
            # lookup_name returns the integer value directly
            enum_descriptor&.lookup_name(value) || 0
          else
            value.to_i
          end
        end
      end

      # Validates that an enum value is not in a list.
      class EnumNotInRule < Base
        def initialize(field:, not_in_list:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @not_in_list = not_in_list
          @ignore = ignore
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if @ignore == :IGNORE_ALWAYS

          numeric_value = enum_to_int(value, @field.subtype)
          return if @ignore == :IGNORE_IF_UNPOPULATED && numeric_value.zero?

          return unless @not_in_list.include?(numeric_value)

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :enum
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "enum.not_in",
              message: "value must not be in [#{@not_in_list.join(', ')}]"
            )
            violation.field_value = value
            context.add(violation)
          end
        end

        private

        def enum_to_int(value, enum_descriptor)
          if value.is_a?(Symbol)
            # lookup_name returns the integer value directly
            enum_descriptor&.lookup_name(value) || 0
          else
            value.to_i
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
              message: "type URL must be one of: #{@type_urls.to_a.join(", ")}"
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
              message: "type URL must not be one of: #{@type_urls.to_a.join(", ")}"
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
          return if values.nil? || values.size.zero?
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
          # Check if item is a protobuf message (not primitive, not RepeatedField/Map)
          return unless item.is_a?(Google::Protobuf::MessageExts)

          descriptor = item.class.descriptor
          rules = @factory.get(descriptor)

          rules.each do |rule|
            rule.validate(context, item)
            break if context.done?
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
          return if map_value.nil? || map_value.size.zero?
          return if @ignore == :IGNORE_ALWAYS

          field_elem = FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: :message
          )

          context.with_field_path_element(field_elem) do
            map_value.each do |key, _value|
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
          return if map_value.nil? || map_value.size.zero?
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
          # Check if value is a protobuf message (not primitive, not RepeatedField/Map)
          return unless value.is_a?(Google::Protobuf::MessageExts)

          descriptor = value.class.descriptor
          rules = @factory.get(descriptor)

          rules.each do |rule|
            rule.validate(context, value)
            break if context.done?
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

      # Base class for direct field validation rules (not using CEL).
      class DirectFieldRule < Base
        def initialize(field:, constraint_id:, message:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @ignore = ignore
          @constraint_id = constraint_id
          @message = message
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(value)

          return if check_value(value)

          field_elem = build_field_path_element
          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: @constraint_id,
              message: @message
            )
            violation.field_value = value
            context.add(violation)
          end
        end

        protected

        def check_value(value)
          raise NotImplementedError, "Subclasses must implement #check_value"
        end

        private

        def should_ignore?(value)
          # Handle both symbol and integer enum values from protobuf
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            empty_value?(value)
          else
            false
          end
        end

        def normalize_ignore(ignore)
          return ignore if ignore.is_a?(Symbol)

          case ignore
          when 0 then :IGNORE_UNSPECIFIED
          when 1 then :IGNORE_IF_ZERO_VALUE
          when 3 then :IGNORE_ALWAYS
          else :IGNORE_UNSPECIFIED
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

        def build_field_path_element
          FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: @field.type
          )
        end
      end

      # Validates numeric greater than.
      class NumericGtRule < DirectFieldRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt",
            message: "value must be greater than #{bound}"
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value > @bound
        end
      end

      # Validates numeric greater than or equal.
      class NumericGteRule < DirectFieldRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte",
            message: "value must be greater than or equal to #{bound}"
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value >= @bound
        end
      end

      # Validates numeric less than.
      class NumericLtRule < DirectFieldRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.lt",
            message: "value must be less than #{bound}"
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value < @bound
        end
      end

      # Validates numeric less than or equal.
      class NumericLteRule < DirectFieldRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.lte",
            message: "value must be less than or equal to #{bound}"
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value <= @bound
        end
      end

      # Validates numeric const.
      class NumericConstRule < DirectFieldRule
        def initialize(field:, const:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.const",
            message: "value must equal #{const}"
          )
          @const = const
        end

        protected

        def check_value(value)
          value == @const
        end
      end

      # Validates numeric in list.
      class NumericInRule < DirectFieldRule
        def initialize(field:, values:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.in",
            message: "value must be in [#{values.join(", ")}]"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          @values.include?(value)
        end
      end

      # Validates numeric not in list.
      class NumericNotInRule < DirectFieldRule
        def initialize(field:, values:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.not_in",
            message: "value must not be in [#{values.join(", ")}]"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          !@values.include?(value)
        end
      end

      # Validates bool const.
      class BoolConstRule < DirectFieldRule
        def initialize(field:, const:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bool.const",
            message: "value must be #{const}"
          )
          @const = const
        end

        protected

        def check_value(value)
          value == @const
        end
      end

      # Validates float/double is finite.
      class FloatFiniteRule < DirectFieldRule
        def initialize(field:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.finite",
            message: "value must be finite"
          )
        end

        protected

        def check_value(value)
          !value.nan? && !value.infinite?
        end
      end

      # Combined range rules - inclusive (gt < lt means inside range)
      class NumericGtLtRule < DirectFieldRule
        def initialize(field:, gt:, lt:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt_lt",
            message: "value must be greater than #{gt} and less than #{lt}"
          )
          @gt = gt
          @lt = lt
        end

        protected

        def check_value(value)
          value > @gt && value < @lt
        end
      end

      class NumericGteLteRule < DirectFieldRule
        def initialize(field:, gte:, lte:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte_lte",
            message: "value must be greater than or equal to #{gte} and less than or equal to #{lte}"
          )
          @gte = gte
          @lte = lte
        end

        protected

        def check_value(value)
          value >= @gte && value <= @lte
        end
      end

      class NumericGtLteRule < DirectFieldRule
        def initialize(field:, gt:, lte:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt_lte",
            message: "value must be greater than #{gt} and less than or equal to #{lte}"
          )
          @gt = gt
          @lte = lte
        end

        protected

        def check_value(value)
          value > @gt && value <= @lte
        end
      end

      class NumericGteLtRule < DirectFieldRule
        def initialize(field:, gte:, lt:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte_lt",
            message: "value must be greater than or equal to #{gte} and less than #{lt}"
          )
          @gte = gte
          @lt = lt
        end

        protected

        def check_value(value)
          value >= @gte && value < @lt
        end
      end

      # Combined range rules - exclusive (gt > lt means outside range)
      class NumericGtLtExclusiveRule < DirectFieldRule
        def initialize(field:, gt:, lt:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt_lt_exclusive",
            message: "value must be greater than #{gt} or less than #{lt}"
          )
          @gt = gt
          @lt = lt
        end

        protected

        def check_value(value)
          value > @gt || value < @lt
        end
      end

      class NumericGteLteExclusiveRule < DirectFieldRule
        def initialize(field:, gte:, lte:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte_lte_exclusive",
            message: "value must be greater than or equal to #{gte} or less than or equal to #{lte}"
          )
          @gte = gte
          @lte = lte
        end

        protected

        def check_value(value)
          value >= @gte || value <= @lte
        end
      end

      class NumericGtLteExclusiveRule < DirectFieldRule
        def initialize(field:, gt:, lte:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt_lte_exclusive",
            message: "value must be greater than #{gt} or less than or equal to #{lte}"
          )
          @gt = gt
          @lte = lte
        end

        protected

        def check_value(value)
          value > @gt || value <= @lte
        end
      end

      class NumericGteLtExclusiveRule < DirectFieldRule
        def initialize(field:, gte:, lt:, type_name:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte_lt_exclusive",
            message: "value must be greater than or equal to #{gte} or less than #{lt}"
          )
          @gte = gte
          @lt = lt
        end

        protected

        def check_value(value)
          value >= @gte || value < @lt
        end
      end

      # String validation rules

      # Validates string const.
      class StringConstRule < DirectFieldRule
        def initialize(field:, const:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.const",
            message: "value must equal \"#{const}\""
          )
          @const = const
        end

        protected

        def check_value(value)
          value == @const
        end
      end

      # Validates string length (in unicode codepoints).
      class StringLenRule < DirectFieldRule
        def initialize(field:, len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.len",
            message: "value length must be #{len} characters"
          )
          @len = len
        end

        protected

        def check_value(value)
          value.length == @len
        end
      end

      # Validates string minimum length.
      class StringMinLenRule < DirectFieldRule
        def initialize(field:, min_len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.min_len",
            message: "value length must be at least #{min_len} characters"
          )
          @min_len = min_len
        end

        protected

        def check_value(value)
          value.length >= @min_len
        end
      end

      # Validates string maximum length.
      class StringMaxLenRule < DirectFieldRule
        def initialize(field:, max_len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.max_len",
            message: "value length must be at most #{max_len} characters"
          )
          @max_len = max_len
        end

        protected

        def check_value(value)
          value.length <= @max_len
        end
      end

      # Validates string byte length.
      class StringLenBytesRule < DirectFieldRule
        def initialize(field:, len_bytes:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.len_bytes",
            message: "value length must be #{len_bytes} bytes"
          )
          @len_bytes = len_bytes
        end

        protected

        def check_value(value)
          value.bytesize == @len_bytes
        end
      end

      # Validates string minimum byte length.
      class StringMinBytesRule < DirectFieldRule
        def initialize(field:, min_bytes:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.min_bytes",
            message: "value length must be at least #{min_bytes} bytes"
          )
          @min_bytes = min_bytes
        end

        protected

        def check_value(value)
          value.bytesize >= @min_bytes
        end
      end

      # Validates string maximum byte length.
      class StringMaxBytesRule < DirectFieldRule
        def initialize(field:, max_bytes:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.max_bytes",
            message: "value length must be at most #{max_bytes} bytes"
          )
          @max_bytes = max_bytes
        end

        protected

        def check_value(value)
          value.bytesize <= @max_bytes
        end
      end

      # Validates string matches pattern.
      class StringPatternRule < DirectFieldRule
        def initialize(field:, pattern:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.pattern",
            message: "value must match pattern '#{pattern}'"
          )
          @pattern = Regexp.new(pattern)
        end

        protected

        def check_value(value)
          @pattern.match?(value)
        end
      end

      # Validates string prefix.
      class StringPrefixRule < DirectFieldRule
        def initialize(field:, prefix:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.prefix",
            message: "value must have prefix \"#{prefix}\""
          )
          @prefix = prefix
        end

        protected

        def check_value(value)
          value.start_with?(@prefix)
        end
      end

      # Validates string suffix.
      class StringSuffixRule < DirectFieldRule
        def initialize(field:, suffix:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.suffix",
            message: "value must have suffix \"#{suffix}\""
          )
          @suffix = suffix
        end

        protected

        def check_value(value)
          value.end_with?(@suffix)
        end
      end

      # Validates string contains.
      class StringContainsRule < DirectFieldRule
        def initialize(field:, contains:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.contains",
            message: "value must contain \"#{contains}\""
          )
          @contains = contains
        end

        protected

        def check_value(value)
          value.include?(@contains)
        end
      end

      # Validates string not contains.
      class StringNotContainsRule < DirectFieldRule
        def initialize(field:, not_contains:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.not_contains",
            message: "value must not contain \"#{not_contains}\""
          )
          @not_contains = not_contains
        end

        protected

        def check_value(value)
          !value.include?(@not_contains)
        end
      end

      # Validates string in list.
      class StringInRule < DirectFieldRule
        def initialize(field:, values:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.in",
            message: "value must be in [#{values.map { |v| "\"#{v}\"" }.join(", ")}]"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          @values.include?(value)
        end
      end

      # Validates string not in list.
      class StringNotInRule < DirectFieldRule
        def initialize(field:, values:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.not_in",
            message: "value must not be in [#{values.map { |v| "\"#{v}\"" }.join(", ")}]"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          !@values.include?(value)
        end
      end

      # Validates string is valid email.
      class StringEmailRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.email",
            message: "value must be a valid email address"
          )
        end

        protected

        def check_value(value)
          return false if value.empty?

          # Email validation pattern
          pattern = %r{\A[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z}
          value.match?(pattern)
        end
      end

      # Validates string is valid hostname.
      class StringHostnameRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.hostname",
            message: "value must be a valid hostname"
          )
        end

        protected

        def check_value(value)
          return false if value.empty?
          return false if value.length > 253

          # Hostname pattern - each label 1-63 chars, alphanumeric and hyphens
          pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?\z/
          value.match?(pattern)
        end
      end

      # Validates string is valid IP address.
      class StringIpRule < DirectFieldRule
        def initialize(field:, version: 0, ignore: :IGNORE_UNSPECIFIED)
          constraint_id = case version
                          when 4 then "string.ipv4"
                          when 6 then "string.ipv6"
                          else "string.ip"
                          end
          message = case version
                    when 4 then "value must be a valid IPv4 address"
                    when 6 then "value must be a valid IPv6 address"
                    else "value must be a valid IP address"
                    end
          super(
            field: field,
            ignore: ignore,
            constraint_id: constraint_id,
            message: message
          )
          @version = version
        end

        protected

        def check_value(value)
          return false if value.empty?

          require "ipaddr"
          begin
            addr = IPAddr.new(value)
            case @version
            when 4 then addr.ipv4?
            when 6 then addr.ipv6?
            else true
            end
          rescue IPAddr::InvalidAddressError
            false
          end
        end
      end

      # Validates string is valid URI.
      class StringUriRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.uri",
            message: "value must be a valid URI"
          )
        end

        protected

        def check_value(value)
          return false if value.empty?

          require "uri"
          begin
            uri = URI.parse(value)
            uri.scheme && !uri.scheme.empty?
          rescue URI::InvalidURIError
            false
          end
        end
      end

      # Validates string is valid URI reference.
      class StringUriRefRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.uri_ref",
            message: "value must be a valid URI reference"
          )
        end

        protected

        def check_value(value)
          return true if value.empty?

          require "uri"
          begin
            URI.parse(value)
            true
          rescue URI::InvalidURIError
            false
          end
        end
      end

      # Validates string is valid UUID.
      class StringUuidRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.uuid",
            message: "value must be a valid UUID"
          )
        end

        protected

        def check_value(value)
          pattern = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/
          value.match?(pattern)
        end
      end

      # Validates bytes length.
      class BytesLenRule < DirectFieldRule
        def initialize(field:, len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.len",
            message: "value length must be #{len} bytes"
          )
          @len = len
        end

        protected

        def check_value(value)
          value.bytesize == @len
        end
      end

      # Validates bytes minimum length.
      class BytesMinLenRule < DirectFieldRule
        def initialize(field:, min_len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.min_len",
            message: "value length must be at least #{min_len} bytes"
          )
          @min_len = min_len
        end

        protected

        def check_value(value)
          value.bytesize >= @min_len
        end
      end

      # Validates bytes maximum length.
      class BytesMaxLenRule < DirectFieldRule
        def initialize(field:, max_len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.max_len",
            message: "value length must be at most #{max_len} bytes"
          )
          @max_len = max_len
        end

        protected

        def check_value(value)
          value.bytesize <= @max_len
        end
      end

      # Validates bytes const.
      class BytesConstRule < DirectFieldRule
        def initialize(field:, const:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.const",
            message: "value must equal the specified bytes"
          )
          @const = const
        end

        protected

        def check_value(value)
          value == @const
        end
      end

      # Validates bytes matches pattern.
      class BytesPatternRule < DirectFieldRule
        def initialize(field:, pattern:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.pattern",
            message: "value must match pattern '#{pattern}'"
          )
          @pattern = Regexp.new(pattern)
        end

        protected

        def check_value(value)
          @pattern.match?(value)
        end
      end

      # Validates bytes prefix.
      class BytesPrefixRule < DirectFieldRule
        def initialize(field:, prefix:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.prefix",
            message: "value must have the specified prefix"
          )
          @prefix = prefix
        end

        protected

        def check_value(value)
          value.start_with?(@prefix)
        end
      end

      # Validates bytes suffix.
      class BytesSuffixRule < DirectFieldRule
        def initialize(field:, suffix:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.suffix",
            message: "value must have the specified suffix"
          )
          @suffix = suffix
        end

        protected

        def check_value(value)
          value.end_with?(@suffix)
        end
      end

      # Validates bytes contains.
      class BytesContainsRule < DirectFieldRule
        def initialize(field:, contains:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.contains",
            message: "value must contain the specified bytes"
          )
          @contains = contains
        end

        protected

        def check_value(value)
          value.include?(@contains)
        end
      end

      # Validates bytes in list.
      class BytesInRule < DirectFieldRule
        def initialize(field:, values:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.in",
            message: "value must be in the specified list"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          @values.include?(value)
        end
      end

      # Validates bytes not in list.
      class BytesNotInRule < DirectFieldRule
        def initialize(field:, values:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.not_in",
            message: "value must not be in the specified list"
          )
          @values = values.to_set
        end

        protected

        def check_value(value)
          !@values.include?(value)
        end
      end

      # Validates bytes is valid IP address.
      class BytesIpRule < DirectFieldRule
        def initialize(field:, version: 0, ignore: :IGNORE_UNSPECIFIED)
          constraint_id = case version
                          when 4 then "bytes.ipv4"
                          when 6 then "bytes.ipv6"
                          else "bytes.ip"
                          end
          message = case version
                    when 4 then "value must be a valid IPv4 address"
                    when 6 then "value must be a valid IPv6 address"
                    else "value must be a valid IP address"
                    end
          super(
            field: field,
            ignore: ignore,
            constraint_id: constraint_id,
            message: message
          )
          @version = version
        end

        protected

        def check_value(value)
          case @version
          when 4
            value.bytesize == 4
          when 6
            value.bytesize == 16
          else
            value.bytesize == 4 || value.bytesize == 16
          end
        end
      end
    end
  end
end
