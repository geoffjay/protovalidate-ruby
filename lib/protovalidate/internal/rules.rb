# frozen_string_literal: true

require_relative "cel_helpers"

module Protovalidate
  module Internal
    # Contains all rule implementations for validation.
    module Rules
      # Helper module for building rule paths.
      # Rule paths describe the path through FieldRules to the specific constraint that was violated.
      module RulePath
        # FieldRules field numbers for each type constraint
        FIELD_RULES_NUMBERS = {
          float: 1, double: 2, int32: 3, int64: 4,
          uint32: 5, uint64: 6, sint32: 7, sint64: 8,
          fixed32: 9, fixed64: 10, sfixed32: 11, sfixed64: 12,
          bool: 13, string: 14, bytes: 15, enum: 16,
          repeated: 18, map: 19, any: 20, duration: 21, timestamp: 22,
          cel: 23, required: 25, ignore: 27
        }.freeze

        # Numeric rules field numbers (shared by all numeric types)
        NUMERIC_RULE_NUMBERS = {
          const: 1, lt: 2, lte: 3, gt: 4, gte: 5, in: 6, not_in: 7, finite: 8
        }.freeze

        # String rules field numbers
        STRING_RULE_NUMBERS = {
          const: 1, len: 19, min_len: 2, max_len: 3,
          len_bytes: 20, min_bytes: 4, max_bytes: 5,
          pattern: 6, prefix: 7, suffix: 8, contains: 9, not_contains: 23,
          in: 10, not_in: 11, email: 12, hostname: 13, ip: 14, ipv4: 15, ipv6: 16,
          uri: 17, uri_ref: 18, address: 21, uuid: 22, well_known_regex: 24,
          ip_with_prefixlen: 26, ipv4_with_prefixlen: 27, ipv6_with_prefixlen: 28,
          ip_prefix: 29, ipv4_prefix: 30, ipv6_prefix: 31, host_and_port: 32, tuuid: 33
        }.freeze

        # Bytes rules field numbers
        BYTES_RULE_NUMBERS = {
          const: 1, len: 13, min_len: 2, max_len: 3,
          pattern: 4, prefix: 5, suffix: 6, contains: 7,
          in: 8, not_in: 9, ip: 10, ipv4: 11, ipv6: 12
        }.freeze

        # Bool rules field numbers
        BOOL_RULE_NUMBERS = {
          const: 1
        }.freeze

        # Enum rules field numbers
        ENUM_RULE_NUMBERS = {
          const: 1, defined_only: 2, in: 3, not_in: 4
        }.freeze

        # Repeated rules field numbers
        REPEATED_RULE_NUMBERS = {
          min_items: 1, max_items: 2, unique: 3, items: 4
        }.freeze

        # Map rules field numbers
        MAP_RULE_NUMBERS = {
          min_pairs: 1, max_pairs: 2, keys: 4, values: 5
        }.freeze

        # Any rules field numbers
        ANY_RULE_NUMBERS = {
          in: 2, not_in: 3
        }.freeze

        # Duration rules field numbers
        DURATION_RULE_NUMBERS = {
          const: 2, lt: 3, lte: 4, gt: 5, gte: 6, in: 7, not_in: 8
        }.freeze

        # Timestamp rules field numbers
        TIMESTAMP_RULE_NUMBERS = {
          const: 2, lt: 3, lte: 4, gt: 5, gte: 6, lt_now: 7, gt_now: 8, within: 9
        }.freeze

        class << self
          # Builds a rule path for a type-specific rule
          # NOTE: Returns elements in REVERSE order because finalize_violations will reverse them
          #
          # @param type_name [Symbol] The type name (:string, :int32, :enum, etc.)
          # @param rule_name [Symbol] The rule name (:const, :min_len, :gt, etc.)
          # @return [Array<FieldPathElement>] The rule path elements (in reverse order)
          def build(type_name, rule_name)
            type_field_number = FIELD_RULES_NUMBERS[type_name]
            return [] unless type_field_number

            rule_numbers = case type_name
                           when :string then STRING_RULE_NUMBERS
                           when :bytes then BYTES_RULE_NUMBERS
                           when :bool then BOOL_RULE_NUMBERS
                           when :enum then ENUM_RULE_NUMBERS
                           when :repeated then REPEATED_RULE_NUMBERS
                           when :map then MAP_RULE_NUMBERS
                           when :any then ANY_RULE_NUMBERS
                           when :duration then DURATION_RULE_NUMBERS
                           when :timestamp then TIMESTAMP_RULE_NUMBERS
                           else NUMERIC_RULE_NUMBERS
                           end

            rule_field_number = rule_numbers[rule_name]
            return [] unless rule_field_number

            rule_field_type = rule_field_type_for(type_name, rule_name)

            # Return in REVERSE order - will be reversed again by finalize_violations
            [
              FieldPathElement.new(
                field_number: rule_field_number,
                field_name: rule_name.to_s,
                field_type: rule_field_type
              ),
              FieldPathElement.new(
                field_number: type_field_number,
                field_name: type_name.to_s,
                field_type: :message
              )
            ]
          end

          # Builds a rule path for required constraint
          #
          # @return [Array<FieldPathElement>] The rule path elements
          def required
            [
              FieldPathElement.new(
                field_number: FIELD_RULES_NUMBERS[:required],
                field_name: "required",
                field_type: :bool
              )
            ]
          end

          private

          def rule_field_type_for(type_name, rule_name)
            # Most rules are the same type as the field type
            case rule_name
            when :const
              case type_name
              when :string then :string
              when :bytes then :bytes
              when :bool then :bool
              when :enum then :int32
              when :duration, :timestamp then :message
              else numeric_type_for(type_name)
              end
            when :lt, :lte, :gt, :gte
              case type_name
              when :duration, :timestamp then :message
              else numeric_type_for(type_name)
              end
            when :in, :not_in
              case type_name
              when :string then :string
              when :bytes then :bytes
              when :enum, :any then type_name == :any ? :string : :int32
              else numeric_type_for(type_name)
              end
            when :len, :min_len, :max_len, :len_bytes, :min_bytes, :max_bytes,
                 :min_items, :max_items, :min_pairs, :max_pairs
              :uint64
            when :pattern then :string
            when :prefix, :suffix, :contains, :not_contains then type_name == :bytes ? :bytes : :string
            when :email, :hostname, :ip, :ipv4, :ipv6, :uri, :uri_ref, :address, :uuid, :tuuid,
                 :ip_with_prefixlen, :ipv4_with_prefixlen, :ipv6_with_prefixlen,
                 :ip_prefix, :ipv4_prefix, :ipv6_prefix,
                 :host_and_port, :unique, :defined_only, :finite, :lt_now, :gt_now
              :bool
            when :well_known_regex
              :enum
            when :within then :message
            when :items, :keys, :values then :message
            else :message
            end
          end

          def numeric_type_for(type_name)
            # Return the actual field type, not the wire type
            type_name
          end
        end
      end

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
        # Field number for 'cel' in FieldConstraints
        CEL_FIELD_NUMBER = 23

        def initialize(field:, program:, rule:, cel_env:, ignore: :IGNORE_UNSPECIFIED, oneof_name: nil, cel_index: 0)
          super()
          @field = field
          @program = program
          @rule = rule
          @cel_env = cel_env
          @ignore = ignore
          @oneof_name = oneof_name
          @cel_index = cel_index
        end

        def validate(context, message)
          return if context.done?

          # For oneof members, skip validation if not the selected field
          if @oneof_name
            selected = message.send(@oneof_name) rescue nil
            return unless selected&.to_s == @field.name
          end

          value = message.send(@field.name)

          # Handle ignore conditions
          return if should_ignore?(message, value)

          field_elem = build_field_path_element

          context.with_field_path_element(field_elem) do
            activation = CelHelpers.field_to_activation(value, @field)
            result = @program.evaluate(activation)

            unless result == true || (result.respond_to?(:value) && result.value == true)
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: @rule.message || "CEL expression evaluated to false",
                rule_path: build_cel_rule_path
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("CEL evaluation failed for field '#{@field.name}': #{e.message}", cause: e)
        end

        private

        def should_ignore?(message, value)
          # Handle both symbol and integer enum values from protobuf
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            # For fields with explicit presence (proto2 optional, proto3 optional, editions explicit),
            # only ignore if the field is not set. For implicit presence, ignore if zero-value.
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              empty_value?(value)
            end
          when :IGNORE_UNSPECIFIED
            # For IGNORE_UNSPECIFIED, fields with explicit presence should be ignored if not set.
            # For fields with implicit presence, don't ignore (validate even zero values).
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              false
            end
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
          when FalseClass then true # false is the zero/default value for booleans
          when TrueClass then false
          when Array then value.empty?
          when Hash then value.empty?
          when Google::Protobuf::RepeatedField then value.empty?
          when Google::Protobuf::Map then value.size.zero?
          else
            # For proto messages, check if it's the default
            if value.is_a?(Google::Protobuf::MessageExts) && value.respond_to?(:to_h)
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

        def build_cel_rule_path
          [
            FieldPathElement.new(
              field_number: CEL_FIELD_NUMBER,
              field_name: "cel",
              field_type: :message,
              subscript: @cel_index,
              subscript_type: :index
            )
          ]
        end
      end

      # CEL rule for predefined validation constraints defined as extensions.
      class PredefinedCelRule < Base
        def initialize(field:, program:, rule:, cel_env:, ignore: :IGNORE_UNSPECIFIED, field_number: 1161,
                       extension_name: nil, type_rules_field_number: 0, type_rules_field_name: "",
                       extension_value: nil, extension_type: nil, extension_label: nil)
          super()
          @field = field
          @program = program
          @rule = rule
          @cel_env = cel_env
          @ignore = ignore
          @field_number = field_number
          @extension_name = extension_name
          @type_rules_field_number = type_rules_field_number
          @type_rules_field_name = type_rules_field_name
          @extension_value = extension_value
          @extension_type = extension_type
          @extension_label = extension_label
          @decoded_rule_value = decode_extension_value(extension_value, extension_type, extension_label)
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)

          # Handle ignore conditions
          return if should_ignore?(message, value)

          field_elem = build_field_path_element

          context.with_field_path_element(field_elem) do
            activation = CelHelpers.field_to_activation(value, @field)
            # Add the rule value to the activation if we have one
            activation[:rule] = CelHelpers.ruby_to_cel(@decoded_rule_value) if @decoded_rule_value
            result = @program.evaluate(activation)

            # Predefined rules return empty string for success, error message for failure
            result_value = result.respond_to?(:value) ? result.value : result

            # Check if validation failed (non-empty string means error message)
            if result_value.is_a?(String) && !result_value.empty?
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: result_value,
                rule_path: build_predefined_rule_path
              )
              violation.field_value = value
              context.add(violation)
            elsif result_value == false
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: @rule.message.to_s.empty? ? "predefined rule failed" : @rule.message,
                rule_path: build_predefined_rule_path
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("Predefined CEL evaluation failed for field '#{@field.name}': #{e.message}", cause: e)
        end

        private

        def should_ignore?(message, value)
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              empty_value?(value)
            end
          when :IGNORE_UNSPECIFIED
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              false
            end
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
          when FalseClass then true
          when TrueClass then false
          when Array, Google::Protobuf::RepeatedField then value.empty?
          when Hash then value.empty?
          when Google::Protobuf::Map then value.size.zero?
          else
            if value.is_a?(Google::Protobuf::MessageExts) && value.respond_to?(:to_h)
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

        def build_predefined_rule_path
          # The rule path should have two elements (after finalization):
          # 1. The type-specific rules field (e.g., field 14 "string" for StringRules)
          # 2. The extension field with name formatted as [full.extension.name]
          #
          # Note: finalize_violations reverses the rule_path, so we build in reverse order
          extension_field_name = @extension_name ? "[#{@extension_name}]" : ""

          [
            FieldPathElement.new(
              field_number: @field_number,
              field_name: extension_field_name,
              field_type: @extension_type || :bool
            ),
            FieldPathElement.new(
              field_number: @type_rules_field_number,
              field_name: @type_rules_field_name,
              field_type: :message
            )
          ]
        end

        # Decodes the binary extension value to the appropriate Ruby type
        def decode_extension_value(value, field_type, field_label = nil)
          return nil if value.nil?

          # Handle repeated fields (packed encoding)
          if field_label == :repeated
            return decode_packed_values(value, field_type)
          end

          case field_type
          when :float
            # 32-bit float in little-endian
            value.unpack1("e")
          when :double
            # 64-bit double in little-endian
            value.unpack1("E")
          when :int32, :sint32, :sfixed32
            # 32-bit signed integer
            value.is_a?(Integer) ? value : value.unpack1("l<")
          when :int64, :sint64, :sfixed64
            # 64-bit signed integer
            value.is_a?(Integer) ? value : value.unpack1("q<")
          when :uint32, :fixed32
            # 32-bit unsigned integer
            value.is_a?(Integer) ? value : value.unpack1("L<")
          when :uint64, :fixed64
            # 64-bit unsigned integer
            value.is_a?(Integer) ? value : value.unpack1("Q<")
          when :bool
            # Boolean - varint 0 or 1
            value.is_a?(Integer) ? value != 0 : value.unpack1("C") != 0
          when :string, :bytes
            # Already a string
            value.is_a?(String) ? value : value.to_s
          else
            # For other types (enum, message), return as-is
            value
          end
        end

        # Decodes packed repeated values from binary data
        def decode_packed_values(data, element_type)
          return [] if data.nil? || data.empty?

          results = []
          data = data.b
          pos = 0

          case element_type
          when :int32, :int64, :uint32, :uint64, :sint32, :sint64, :enum
            # Varints
            while pos < data.bytesize
              value, pos = decode_varint(data, pos)
              break if value.nil?

              # Handle signed types
              case element_type
              when :sint32
                value = (value >> 1) ^ -(value & 1)
              when :sint64
                value = (value >> 1) ^ -(value & 1)
              when :int32
                # Sign-extend 32-bit values
                value = value > 0x7FFFFFFF ? value - 0x100000000 : value
              end

              results << value
            end
          when :fixed32, :sfixed32, :float
            # 32-bit fixed
            while pos + 4 <= data.bytesize
              if element_type == :float
                results << data[pos, 4].unpack1("e")
              elsif element_type == :sfixed32
                results << data[pos, 4].unpack1("l<")
              else
                results << data[pos, 4].unpack1("L<")
              end
              pos += 4
            end
          when :fixed64, :sfixed64, :double
            # 64-bit fixed
            while pos + 8 <= data.bytesize
              if element_type == :double
                results << data[pos, 8].unpack1("E")
              elsif element_type == :sfixed64
                results << data[pos, 8].unpack1("q<")
              else
                results << data[pos, 8].unpack1("Q<")
              end
              pos += 8
            end
          when :bool
            while pos < data.bytesize
              value, pos = decode_varint(data, pos)
              break if value.nil?

              results << (value != 0)
            end
          else
            return data
          end

          results
        end

        def decode_varint(data, pos)
          result = 0
          shift = 0

          loop do
            return [nil, nil] if pos >= data.bytesize

            byte = data.getbyte(pos)
            pos += 1

            result |= (byte & 0x7f) << shift

            return [result, pos] if byte.nobits?(0x80)

            shift += 7
            return [nil, nil] if shift > 63
          end
        end
      end

      # CEL rule for predefined validation constraints on wrapper types (StringValue, etc.)
      class WrapperPredefinedCelRule < Base
        def initialize(field:, program:, rule:, cel_env:, ignore: :IGNORE_UNSPECIFIED, field_number: 1161,
                       extension_name: nil, type_rules_field_number: 0, type_rules_field_name: "",
                       extension_value: nil, extension_type: nil, extension_label: nil)
          super()
          @field = field
          @program = program
          @rule = rule
          @cel_env = cel_env
          @ignore = ignore
          @field_number = field_number
          @extension_name = extension_name
          @type_rules_field_number = type_rules_field_number
          @type_rules_field_name = type_rules_field_name
          @extension_value = extension_value
          @extension_type = extension_type
          @extension_label = extension_label
          @decoded_rule_value = decode_extension_value(extension_value, extension_type, extension_label)
        end

        def validate(context, message)
          return if context.done?

          wrapper = message.send(@field.name)

          # Handle ignore conditions for the wrapper
          return if should_ignore_wrapper?(message, wrapper)

          # Unwrap the value
          return if wrapper.nil?

          value = wrapper.respond_to?(:value) ? wrapper.value : wrapper

          field_elem = build_field_path_element

          context.with_field_path_element(field_elem) do
            # Create activation with unwrapped value
            activation = { this: CelHelpers.ruby_to_cel(value), now: Time.now }
            activation[:rule] = CelHelpers.ruby_to_cel(@decoded_rule_value) if @decoded_rule_value
            result = @program.evaluate(activation)

            result_value = result.respond_to?(:value) ? result.value : result

            if result_value.is_a?(String) && !result_value.empty?
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: result_value,
                rule_path: build_predefined_rule_path
              )
              violation.field_value = value
              context.add(violation)
            elsif result_value == false
              violation = Violation.new(
                constraint_id: @rule.id || "",
                message: @rule.message.to_s.empty? ? "predefined rule failed" : @rule.message,
                rule_path: build_predefined_rule_path
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("Wrapper predefined CEL evaluation failed for field '#{@field.name}': #{e.message}", cause: e)
        end

        private

        def should_ignore_wrapper?(message, wrapper)
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              wrapper.nil?
            end
          when :IGNORE_UNSPECIFIED
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              false
            end
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

        def build_field_path_element
          FieldPathElement.new(
            field_number: @field.number,
            field_name: @field.name,
            field_type: @field.type
          )
        end

        def build_predefined_rule_path
          extension_field_name = @extension_name ? "[#{@extension_name}]" : ""

          [
            FieldPathElement.new(
              field_number: @field_number,
              field_name: extension_field_name,
              field_type: @extension_type || :bool
            ),
            FieldPathElement.new(
              field_number: @type_rules_field_number,
              field_name: @type_rules_field_name,
              field_type: :message
            )
          ]
        end

        def decode_extension_value(value, ext_type, ext_label = nil)
          return nil if value.nil?

          # Handle repeated fields (packed encoding)
          if ext_label == :repeated
            return decode_packed_values(value, ext_type)
          end

          case ext_type
          when :float
            value.unpack1("e")
          when :double
            value.unpack1("E")
          when :int32, :sint32, :sfixed32
            value.is_a?(Integer) ? value : value.unpack1("l<")
          when :int64, :sint64, :sfixed64
            value.is_a?(Integer) ? value : value.unpack1("q<")
          when :uint32, :fixed32
            value.is_a?(Integer) ? value : value.unpack1("L<")
          when :uint64, :fixed64
            value.is_a?(Integer) ? value : value.unpack1("Q<")
          when :bool
            value.is_a?(Integer) ? value != 0 : value.unpack1("C") != 0
          when :string, :bytes
            value.is_a?(String) ? value : value.to_s
          else
            value
          end
        end

        # Decodes packed repeated values from binary data
        def decode_packed_values(data, element_type)
          return [] if data.nil? || data.empty?

          results = []
          data = data.b
          pos = 0

          case element_type
          when :int32, :int64, :uint32, :uint64, :sint32, :sint64, :enum
            while pos < data.bytesize
              value, pos = decode_varint(data, pos)
              break if value.nil?

              case element_type
              when :sint32
                value = (value >> 1) ^ -(value & 1)
              when :sint64
                value = (value >> 1) ^ -(value & 1)
              when :int32
                value = value > 0x7FFFFFFF ? value - 0x100000000 : value
              end

              results << value
            end
          when :fixed32, :sfixed32, :float
            while pos + 4 <= data.bytesize
              if element_type == :float
                results << data[pos, 4].unpack1("e")
              elsif element_type == :sfixed32
                results << data[pos, 4].unpack1("l<")
              else
                results << data[pos, 4].unpack1("L<")
              end
              pos += 4
            end
          when :fixed64, :sfixed64, :double
            while pos + 8 <= data.bytesize
              if element_type == :double
                results << data[pos, 8].unpack1("E")
              elsif element_type == :sfixed64
                results << data[pos, 8].unpack1("q<")
              else
                results << data[pos, 8].unpack1("Q<")
              end
              pos += 8
            end
          when :bool
            while pos < data.bytesize
              value, pos = decode_varint(data, pos)
              break if value.nil?

              results << (value != 0)
            end
          else
            return data
          end

          results
        end

        def decode_varint(data, pos)
          result = 0
          shift = 0

          loop do
            return [nil, nil] if pos >= data.bytesize

            byte = data.getbyte(pos)
            pos += 1

            result |= (byte & 0x7f) << shift

            return [result, pos] if byte.nobits?(0x80)

            shift += 7
            return [nil, nil] if shift > 63
          end
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
          when FalseClass then true # false is the default/zero value for booleans
          when TrueClass then false
          when Array then value.empty?
          when Hash then value.empty?
          else
            false
          end
        end
      end

      # Validates that a oneof field is set (for protobuf oneof declarations).
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

          # Build field path element for the oneof
          field_elem = FieldPathElement.new(
            field_number: 0,
            field_name: @oneof.name,
            field_type: nil
          )

          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "required",
              message: "exactly one field is required in oneof"
            )
            context.add(violation)
          end
        end
      end

      # Validates message-level oneof constraints.
      # These are specified via MessageRules.oneof and are different from protobuf oneofs.
      class MessageOneofRule < Base
        def initialize(fields:, required:, descriptor:)
          super()
          @fields = fields
          @required = required
          @descriptor = descriptor
        end

        def validate(context, message)
          return if context.done?

          # Count how many of the specified fields are set
          set_count = 0
          set_fields = []

          @fields.each do |field_name|
            field = find_field(field_name)
            next unless field

            if field_is_set?(message, field)
              set_count += 1
              set_fields << field_name
            end
          end

          # Validate based on the constraint
          if @required && set_count == 0
            # Required but none set
            violation = Violation.new(
              constraint_id: "message.oneof",
              message: "one of #{@fields.join(", ")} must be set"
            )
            context.add(violation)
          elsif set_count > 1
            # More than one set - always invalid for oneof
            violation = Violation.new(
              constraint_id: "message.oneof",
              message: "only one of #{set_fields.join(", ")} can be set"
            )
            context.add(violation)
          end
        end

        private

        def find_field(field_name)
          @descriptor.each do |field|
            return field if field.name == field_name
          end
          nil
        end

        def field_is_set?(message, field)
          # Check if field has presence tracking
          if message.respond_to?("has_#{field.name}?")
            return message.send("has_#{field.name}?")
          end

          value = message.send(field.name)
          return false if value.nil?

          case field.type
          when :message
            # Messages are set if not nil
            true
          when :string
            !value.empty?
          when :bytes
            !value.empty?
          when :bool
            # For message-level oneofs with implicit presence, false (default) means not set
            value == true
          else
            # Numbers: 0 is considered not set for synthetic oneofs
            !value.zero?
          end
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
              message: "value must be a defined enum value",
              rule_path: RulePath.build(:enum, :defined_only)
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
              message: "value must equal #{@const_value}",
              rule_path: RulePath.build(:enum, :const)
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
              message: "value must be in [#{@in_list.join(', ')}]",
              rule_path: RulePath.build(:enum, :in)
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
              message: "value must not be in [#{@not_in_list.join(', ')}]",
              rule_path: RulePath.build(:enum, :not_in)
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
        def initialize(field:, item_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED, item_rules: [])
          super()
          @field = field
          @item_constraints = item_constraints
          @factory = factory
          @ignore = ignore
          @item_rules = item_rules
        end

        def validate(context, message)
          return if context.done?

          values = message.send(@field.name)
          return if values.nil? || values.size.zero?
          return if @ignore == :IGNORE_ALWAYS

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

        private

        def validate_item(context, item)
          # For message items, recursively validate using the factory
          if item.is_a?(Google::Protobuf::MessageExts)
            descriptor = item.class.descriptor
            rules = @factory.get(descriptor)

            rules.each do |rule|
              rule.validate(context, item)
              break if context.done?
            end
          else
            # For scalar items, use the pre-compiled item rules
            @item_rules.each do |rule|
              rule.validate_item(context, item)
              break if context.done?
            end
          end
        end
      end

      # Validates keys in a map field.
      class MapKeysRule < Base
        def initialize(field:, key_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED, key_rules: [], key_type: nil, value_type: nil)
          super()
          @field = field
          @key_constraints = key_constraints
          @factory = factory
          @ignore = ignore
          @key_rules = key_rules
          @key_type = key_type
          @value_type = value_type
        end

        def validate(context, message)
          return if context.done?

          map_value = message.send(@field.name)
          return if map_value.nil? || map_value.size.zero?
          return if @ignore == :IGNORE_ALWAYS

          map_value.each do |key, _value|
            break if context.done?

            key_elem = build_key_element(key)
            context.with_field_path_element(key_elem) do
              # Apply key validation rules
              @key_rules.each do |rule|
                rule.validate_item(context, key)
                break if context.done?
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
            subscript_type: subscript_type,
            key_type: @key_type,
            value_type: @value_type
          )
        end
      end

      # Validates values in a map field.
      class MapValuesRule < Base
        def initialize(field:, value_constraints:, factory:, ignore: :IGNORE_UNSPECIFIED, value_rules: [], key_type: nil, value_type: nil)
          super()
          @field = field
          @value_constraints = value_constraints
          @factory = factory
          @ignore = ignore
          @value_rules = value_rules
          @key_type = key_type
          @value_type = value_type
        end

        def validate(context, message)
          return if context.done?

          map_value = message.send(@field.name)
          return if map_value.nil? || map_value.size.zero?
          return if @ignore == :IGNORE_ALWAYS

          map_value.each do |key, value|
            break if context.done?

            key_elem = build_key_element(key)
            context.with_field_path_element(key_elem) do
              validate_value(context, value)
            end
          end
        end

        private

        def validate_value(context, value)
          # For message values, recursively validate
          if value.is_a?(Google::Protobuf::MessageExts)
            descriptor = value.class.descriptor
            rules = @factory.get(descriptor)

            rules.each do |rule|
              rule.validate(context, value)
              break if context.done?
            end
          else
            # For scalar values, use the pre-compiled value rules
            @value_rules.each do |rule|
              rule.validate_item(context, value)
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
            subscript_type: subscript_type,
            key_type: @key_type,
            value_type: @value_type
          )
        end
      end

      # Base class for direct field validation rules (not using CEL).
      class DirectFieldRule < Base
        def initialize(field:, constraint_id:, message:, ignore: :IGNORE_UNSPECIFIED, rule_path: [], oneof_name: nil)
          super()
          @field = field
          @ignore = ignore
          @constraint_id = constraint_id
          @message = message
          @rule_path = rule_path
          @oneof_name = oneof_name
        end

        def validate(context, message)
          return if context.done?

          # For oneof members, skip validation if not the selected field
          if @oneof_name
            selected = message.send(@oneof_name) rescue nil
            return unless selected&.to_s == @field.name
          end

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          return if check_value(value)

          field_elem = build_field_path_element
          context.with_field_path_element(field_elem) do
            # Add _empty suffix for string fields with empty values
            constraint_id = if value.is_a?(String) && value.empty? && @constraint_id.start_with?("string.")
                              "#{@constraint_id}_empty"
                            else
                              @constraint_id
                            end

            violation = Violation.new(
              constraint_id: constraint_id,
              message: @message,
              rule_path: @rule_path
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

        def should_ignore?(message, value)
          # Handle both symbol and integer enum values from protobuf
          ignore_value = normalize_ignore(@ignore)

          case ignore_value
          when :IGNORE_ALWAYS
            true
          when :IGNORE_IF_UNPOPULATED, :IGNORE_IF_DEFAULT_VALUE, :IGNORE_IF_ZERO_VALUE
            # For fields with explicit presence (proto2 optional, proto3 optional, editions explicit),
            # only ignore if the field is not set. For implicit presence, ignore if zero-value.
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              empty_value?(value)
            end
          when :IGNORE_UNSPECIFIED
            # For IGNORE_UNSPECIFIED, fields with explicit presence should be ignored if not set.
            # For fields with implicit presence, don't ignore (validate even zero values).
            if message.respond_to?("has_#{@field.name}?")
              !message.send("has_#{@field.name}?")
            else
              false
            end
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
          when FalseClass then true # false is the default/zero value for booleans
          when TrueClass then false
          when Array then value.empty?
          when Hash then value.empty?
          when Google::Protobuf::RepeatedField then value.empty?
          when Google::Protobuf::Map then value.size.zero?
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
            message: "value must be greater than #{bound}",
            rule_path: RulePath.build(type_name.to_sym, :gt)
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
            message: "value must be greater than or equal to #{bound}",
            rule_path: RulePath.build(type_name.to_sym, :gte)
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
            message: "value must be less than #{bound}",
            rule_path: RulePath.build(type_name.to_sym, :lt)
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
            message: "value must be less than or equal to #{bound}",
            rule_path: RulePath.build(type_name.to_sym, :lte)
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
            message: "value must equal #{const}",
            rule_path: RulePath.build(type_name.to_sym, :const)
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
            message: "value must be in [#{values.join(", ")}]",
            rule_path: RulePath.build(type_name.to_sym, :in)
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
            message: "value must not be in [#{values.join(", ")}]",
            rule_path: RulePath.build(type_name.to_sym, :not_in)
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
        def initialize(field:, const:, ignore: :IGNORE_UNSPECIFIED, oneof_name: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bool.const",
            message: "value must be #{const}",
            rule_path: RulePath.build(:bool, :const),
            oneof_name: oneof_name
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
            message: "value must be finite",
            rule_path: RulePath.build(type_name.to_sym, :finite)
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
            message: "value must be greater than #{gt} and less than #{lt}",
            rule_path: RulePath.build(type_name.to_sym, :gt)
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
            message: "value must be greater than or equal to #{gte} and less than or equal to #{lte}",
            rule_path: RulePath.build(type_name.to_sym, :gte)
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
            message: "value must be greater than #{gt} and less than or equal to #{lte}",
            rule_path: RulePath.build(type_name.to_sym, :gt)
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
            message: "value must be greater than or equal to #{gte} and less than #{lt}",
            rule_path: RulePath.build(type_name.to_sym, :gte)
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
            message: "value must be greater than #{gt} or less than #{lt}",
            rule_path: RulePath.build(type_name.to_sym, :gt)
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
            message: "value must be greater than or equal to #{gte} or less than or equal to #{lte}",
            rule_path: RulePath.build(type_name.to_sym, :gte)
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
            message: "value must be greater than #{gt} or less than or equal to #{lte}",
            rule_path: RulePath.build(type_name.to_sym, :gt)
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
            message: "value must be greater than or equal to #{gte} or less than #{lt}",
            rule_path: RulePath.build(type_name.to_sym, :gte)
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
            message: "value must equal \"#{const}\"",
            rule_path: RulePath.build(:string, :const)
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
            message: "value length must be #{len} characters",
            rule_path: RulePath.build(:string, :len)
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
            message: "value length must be at least #{min_len} characters",
            rule_path: RulePath.build(:string, :min_len)
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
            message: "value length must be at most #{max_len} characters",
            rule_path: RulePath.build(:string, :max_len)
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
            message: "value length must be #{len_bytes} bytes",
            rule_path: RulePath.build(:string, :len_bytes)
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
            message: "value length must be at least #{min_bytes} bytes",
            rule_path: RulePath.build(:string, :min_bytes)
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
            message: "value length must be at most #{max_bytes} bytes",
            rule_path: RulePath.build(:string, :max_bytes)
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
            message: "value must match pattern '#{pattern}'",
            rule_path: RulePath.build(:string, :pattern)
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
            message: "value must have prefix \"#{prefix}\"",
            rule_path: RulePath.build(:string, :prefix)
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
            message: "value must have suffix \"#{suffix}\"",
            rule_path: RulePath.build(:string, :suffix)
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
            message: "value must contain \"#{contains}\"",
            rule_path: RulePath.build(:string, :contains)
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
            message: "value must not contain \"#{not_contains}\"",
            rule_path: RulePath.build(:string, :not_contains)
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
            message: "value must be in [#{values.map { |v| "\"#{v}\"" }.join(", ")}]",
            rule_path: RulePath.build(:string, :in)
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
            message: "value must not be in [#{values.map { |v| "\"#{v}\"" }.join(", ")}]",
            rule_path: RulePath.build(:string, :not_in)
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
            message: "value must be a valid email address",
            rule_path: RulePath.build(:string, :email)
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
            message: "value must be a valid hostname",
            rule_path: RulePath.build(:string, :hostname)
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
          rule_name = case version
                      when 4 then :ipv4
                      when 6 then :ipv6
                      else :ip
                      end
          super(
            field: field,
            ignore: ignore,
            constraint_id: constraint_id,
            message: message,
            rule_path: RulePath.build(:string, rule_name)
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
            message: "value must be a valid URI",
            rule_path: RulePath.build(:string, :uri)
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
            message: "value must be a valid URI reference",
            rule_path: RulePath.build(:string, :uri_ref)
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
            message: "value must be a valid UUID",
            rule_path: RulePath.build(:string, :uuid)
          )
        end

        protected

        def check_value(value)
          pattern = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/
          value.match?(pattern)
        end
      end

      # Validates that a string is a valid host:port combination.
      class StringHostAndPortRule < DirectFieldRule
        def initialize(field:, port_required: true, ignore: :IGNORE_UNSPECIFIED)
          constraint_id = port_required ? "string.host_and_port" : "string.host_and_port.optional_port"
          super(
            field: field,
            ignore: ignore,
            constraint_id: constraint_id,
            message: port_required ? "value must be a valid host and port pair" : "value must be a host and (optional) port pair",
            rule_path: RulePath.build(:string, :host_and_port)
          )
          @port_required = port_required
          @base_constraint_id = constraint_id
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          # Special handling for empty values - use _empty suffix for constraint_id
          if value.empty?
            @constraint_id = "#{@base_constraint_id}_empty"
          else
            @constraint_id = @base_constraint_id
          end

          unless check_value(value)
            field_elem = build_field_path_element

            context.with_field_path_element(field_elem) do
              violation = Violation.new(
                constraint_id: @constraint_id,
                message: @message,
                rule_path: @rule_path.dup
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        end

        protected

        def check_value(value)
          return false if value.empty? || value =~ /\A\s/ || value =~ /\s\z/

          # Handle IPv6 addresses in brackets
          if value.start_with?("[")
            bracket_end = value.index("]")
            return false unless bracket_end

            host = value[1...bracket_end]
            rest = value[(bracket_end + 1)..]

            return false unless valid_ipv6?(host)

            if rest.empty?
              !@port_required
            elsif rest.start_with?(":")
              port = rest[1..]
              valid_port?(port)
            else
              false
            end
          else
            parts = value.split(":", -1)
            if parts.length == 1
              !@port_required && (valid_hostname?(parts[0]) || valid_ipv4?(parts[0]))
            elsif parts.length == 2
              (valid_hostname?(parts[0]) || valid_ipv4?(parts[0])) && valid_port?(parts[1])
            else
              false
            end
          end
        end

        private

        def valid_hostname?(str)
          return false if str.empty?
          return false if str.length > 253

          # Reject if it looks like an IP address (all numeric labels)
          labels = str.chomp(".").split(".")
          return false if labels.all? { |l| l =~ /\A\d+\z/ }

          # Hostname validation pattern
          pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?\z/
          str.match?(pattern)
        end

        def valid_ipv4?(str)
          return false if str.empty?

          parts = str.split(".")
          return false unless parts.length == 4

          parts.all? do |part|
            return false if part.empty? || part =~ /\A0\d/
            num = part.to_i
            part =~ /\A\d+\z/ && num >= 0 && num <= 255
          end
        end

        def valid_ipv6?(str)
          return false if str.empty?

          require "ipaddr"
          IPAddr.new(str).ipv6?
        rescue IPAddr::InvalidAddressError
          false
        end

        def valid_port?(port_str)
          return false if port_str.empty?
          return false unless port_str.match?(/\A\d+\z/)

          port = port_str.to_i
          port >= 0 && port <= 65535
        end
      end

      # Validates that a string is a valid address (hostname or IP).
      class StringAddressRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.address",
            message: "value must be a valid hostname, or ip address",
            rule_path: RulePath.build(:string, :address)
          )
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          constraint_id = value.empty? ? "string.address_empty" : @constraint_id

          unless check_value(value)
            field_elem = build_field_path_element

            context.with_field_path_element(field_elem) do
              violation = Violation.new(
                constraint_id: constraint_id,
                message: @message,
                rule_path: @rule_path.dup
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        end

        protected

        def check_value(value)
          return false if value.empty?
          valid_hostname?(value) || valid_ip?(value)
        end

        private

        def valid_hostname?(str)
          return false if str.empty?
          return false if str.length > 253

          # Reject if it looks like an IP address (all numeric labels)
          labels = str.chomp(".").split(".")
          return false if labels.all? { |l| l =~ /\A\d+\z/ }

          # Hostname validation pattern
          pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?\z/
          str.match?(pattern)
        end

        def valid_ip?(str)
          require "ipaddr"
          IPAddr.new(str)
          true
        rescue IPAddr::InvalidAddressError
          false
        end
      end

      # Validates that a string is a valid IP address with prefix length (CIDR).
      class StringIpWithPrefixlenRule < DirectFieldRule
        def initialize(field:, version: 0, ignore: :IGNORE_UNSPECIFIED)
          rule_name = case version
                      when 4 then :ipv4_with_prefixlen
                      when 6 then :ipv6_with_prefixlen
                      else :ip_with_prefixlen
                      end
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.#{rule_name}",
            message: "value must be a valid IP address with prefix length",
            rule_path: RulePath.build(:string, rule_name)
          )
          @version = version
          @rule_name = rule_name
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          constraint_id = value.empty? ? "string.#{@rule_name}_empty" : @constraint_id

          unless check_value(value)
            field_elem = build_field_path_element

            context.with_field_path_element(field_elem) do
              violation = Violation.new(
                constraint_id: constraint_id,
                message: @message,
                rule_path: @rule_path.dup
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        end

        protected

        def check_value(value)
          return false if value.empty?
          return false unless value.include?("/")

          require "ipaddr"
          parts = value.split("/")
          return false unless parts.length == 2

          begin
            addr = IPAddr.new(parts[0])
            prefix_len = parts[1].to_i

            return false unless parts[1] =~ /\A\d+\z/

            case @version
            when 4
              return false unless addr.ipv4?
              return false if prefix_len.negative? || prefix_len > 32
            when 6
              return false unless addr.ipv6?
              return false if prefix_len.negative? || prefix_len > 128
            else
              max_prefix = addr.ipv4? ? 32 : 128
              return false if prefix_len.negative? || prefix_len > max_prefix
            end

            true
          rescue IPAddr::InvalidAddressError
            false
          end
        end
      end

      # Validates that a string is a valid IP prefix (network address with prefix length).
      class StringIpPrefixRule < DirectFieldRule
        def initialize(field:, version: 0, ignore: :IGNORE_UNSPECIFIED)
          rule_name = case version
                      when 4 then :ipv4_prefix
                      when 6 then :ipv6_prefix
                      else :ip_prefix
                      end
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.#{rule_name}",
            message: "value must be a valid IP prefix",
            rule_path: RulePath.build(:string, rule_name)
          )
          @version = version
          @rule_name = rule_name
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          constraint_id = value.empty? ? "string.#{@rule_name}_empty" : @constraint_id

          unless check_value(value)
            field_elem = build_field_path_element

            context.with_field_path_element(field_elem) do
              violation = Violation.new(
                constraint_id: constraint_id,
                message: @message,
                rule_path: @rule_path.dup
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        end

        protected

        def check_value(value)
          return false if value.empty?
          return false unless value.include?("/")

          require "ipaddr"
          parts = value.split("/")
          return false unless parts.length == 2

          begin
            return false unless parts[1] =~ /\A\d+\z/

            addr = IPAddr.new(parts[0])
            prefix_len = parts[1].to_i

            case @version
            when 4
              return false unless addr.ipv4?
              return false if prefix_len.negative? || prefix_len > 32
            when 6
              return false unless addr.ipv6?
              return false if prefix_len.negative? || prefix_len > 128
            else
              max_prefix = addr.ipv4? ? 32 : 128
              return false if prefix_len.negative? || prefix_len > max_prefix
            end

            # Check that this is a proper network address (host bits are zero)
            network = IPAddr.new("#{parts[0]}/#{prefix_len}")
            network.to_s == addr.to_s
          rescue IPAddr::InvalidAddressError
            false
          end
        end
      end

      # Validates that a string is a valid TUUID (typed UUID).
      class StringTuuidRule < DirectFieldRule
        def initialize(field:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.tuuid",
            message: "value must be a valid typed UUID",
            rule_path: RulePath.build(:string, :tuuid)
          )
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          constraint_id = value.empty? ? "string.tuuid_empty" : @constraint_id

          unless check_value(value)
            field_elem = build_field_path_element

            context.with_field_path_element(field_elem) do
              violation = Violation.new(
                constraint_id: constraint_id,
                message: @message,
                rule_path: @rule_path.dup
              )
              violation.field_value = value
              context.add(violation)
            end
          end
        end

        protected

        def check_value(value)
          return false if value.empty?

          # TUUID is 32 hex characters WITHOUT dashes (trimmed UUID)
          value.match?(/\A[0-9a-fA-F]{32}\z/)
        end
      end

      # Validates strings against well-known regex patterns (HTTP header names/values).
      class StringWellKnownRegexRule < DirectFieldRule
        KNOWN_REGEX_HTTP_HEADER_NAME = 1
        KNOWN_REGEX_HTTP_HEADER_VALUE = 2

        def initialize(field:, regex_type:, strict: true, ignore: :IGNORE_UNSPECIFIED)
          regex_type_value = regex_type.is_a?(Symbol) ? resolve_regex_type(regex_type) : regex_type.to_i
          type_name = regex_type_value == KNOWN_REGEX_HTTP_HEADER_NAME ? "header_name" : "header_value"
          super(
            field: field,
            ignore: ignore,
            constraint_id: "string.well_known_regex.#{type_name}",
            message: "value must be a valid HTTP #{type_name.tr('_', ' ')}",
            rule_path: RulePath.build(:string, :well_known_regex)
          )
          @regex_type = regex_type_value
          @strict = strict
          @base_constraint_id = "string.well_known_regex.#{type_name}"
        end

        def validate(context, message)
          return if context.done?

          value = message.send(@field.name)
          return if should_ignore?(message, value)

          # Check for empty values - empty is invalid for header names, but valid for header values
          if value.nil? || value.empty?
            if @regex_type == KNOWN_REGEX_HTTP_HEADER_NAME
              report_violation(context, value, "_empty")
            end
            return
          end

          valid = case @regex_type
                  when KNOWN_REGEX_HTTP_HEADER_NAME
                    @strict ? valid_http_header_name_strict?(value) : valid_http_header_name_loose?(value)
                  when KNOWN_REGEX_HTTP_HEADER_VALUE
                    @strict ? valid_http_header_value_strict?(value) : valid_http_header_value_loose?(value)
                  else
                    true
                  end

          report_violation(context, value, "") unless valid
        end

        private

        def resolve_regex_type(type_symbol)
          case type_symbol
          when :KNOWN_REGEX_HTTP_HEADER_NAME then KNOWN_REGEX_HTTP_HEADER_NAME
          when :KNOWN_REGEX_HTTP_HEADER_VALUE then KNOWN_REGEX_HTTP_HEADER_VALUE
          else 0
          end
        end

        def report_violation(context, value, suffix)
          field_elem = build_field_path_element
          context.with_field_path_element(field_elem) do
            violation = Violation.new(
              constraint_id: "#{@base_constraint_id}#{suffix}",
              message: @message,
              rule_path: @rule_path
            )
            violation.field_value = value
            context.add(violation)
          end
        end

        # Strict HTTP header name: RFC 9110 token chars + HTTP/2 pseudo headers
        # token = 1*tchar
        # tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        # Plus: HTTP/2 pseudo headers start with ":"
        def valid_http_header_name_strict?(value)
          return false if value.empty?

          # HTTP/2 pseudo headers (like :authority, :path) start with colon
          if value.start_with?(":")
            # Pseudo header: must be colon followed by valid chars
            return false if value.length == 1 # Solo colon is invalid
            value[1..].each_byte do |byte|
              return false unless valid_token_char?(byte)
            end
            return true
          end

          # Regular header: token chars only, no colons
          value.each_byte do |byte|
            return false unless valid_token_char?(byte)
          end
          true
        end

        # Loose HTTP header name: allows colons except at start/end
        def valid_http_header_name_loose?(value)
          return false if value.empty?
          # No CR, LF, NUL
          value.each_byte do |byte|
            return false if byte == 0x00 || byte == 0x0A || byte == 0x0D
          end
          # No colon at start or end
          return false if value.start_with?(":") || value.end_with?(":")
          true
        end

        # Strict HTTP header value: visible ASCII + SP + HTAB
        def valid_http_header_value_strict?(value)
          value.each_byte do |byte|
            # Allow SP (0x20), HTAB (0x09), visible ASCII (0x21-0x7E)
            # Reject NUL, CR, LF, DEL (0x7F), and other control chars
            next if byte == 0x20 || byte == 0x09 # SP, HTAB
            next if byte >= 0x21 && byte <= 0x7E # visible ASCII
            return false
          end
          true
        end

        # Loose HTTP header value: allows more chars but still rejects NUL, CR, LF
        def valid_http_header_value_loose?(value)
          value.each_byte do |byte|
            return false if byte == 0x00 || byte == 0x0A || byte == 0x0D
          end
          true
        end

        def valid_token_char?(byte)
          # Token chars per RFC 9110
          # ALPHA, DIGIT, or one of: !#$%&'*+-.^_`|~
          return true if (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) # A-Z, a-z
          return true if byte >= 0x30 && byte <= 0x39 # 0-9
          return true if [0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x5E, 0x5F, 0x60, 0x7C, 0x7E].include?(byte)
          # !#$%&'*+-.^_`|~
          false
        end
      end

      # Validates bytes length.
      class BytesLenRule < DirectFieldRule
        def initialize(field:, len:, ignore: :IGNORE_UNSPECIFIED)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "bytes.len",
            message: "value length must be #{len} bytes",
            rule_path: RulePath.build(:bytes, :len)
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
            message: "value length must be at least #{min_len} bytes",
            rule_path: RulePath.build(:bytes, :min_len)
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
            message: "value length must be at most #{max_len} bytes",
            rule_path: RulePath.build(:bytes, :max_len)
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
            message: "value must equal the specified bytes",
            rule_path: RulePath.build(:bytes, :const)
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
            message: "value must match pattern '#{pattern}'",
            rule_path: RulePath.build(:bytes, :pattern)
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
            message: "value must have the specified prefix",
            rule_path: RulePath.build(:bytes, :prefix)
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
            message: "value must have the specified suffix",
            rule_path: RulePath.build(:bytes, :suffix)
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
            message: "value must contain the specified bytes",
            rule_path: RulePath.build(:bytes, :contains)
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
            message: "value must be in the specified list",
            rule_path: RulePath.build(:bytes, :in)
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
            message: "value must not be in the specified list",
            rule_path: RulePath.build(:bytes, :not_in)
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
          rule_name = case version
                      when 4 then :ipv4
                      when 6 then :ipv6
                      else :ip
                      end
          super(
            field: field,
            ignore: ignore,
            constraint_id: constraint_id,
            message: message,
            rule_path: RulePath.build(:bytes, rule_name)
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

      # =========================================================================
      # Item Rules - For validating items in repeated fields (scalars)
      # These rules work with values directly instead of extracting from messages
      # =========================================================================

      # Base class for item validation rules
      class ItemRule < Base
        def initialize(field:, constraint_id:, message:, ignore: :IGNORE_UNSPECIFIED, type_name: nil, rule_element: :const, for_map: false, map_part: nil)
          super()
          @field = field
          @constraint_id = constraint_id
          @message = message
          @ignore = ignore
          @type_name = type_name
          @for_map = for_map
          @map_part = map_part  # :keys or :values
          @rule_path = type_name ? build_rule_path(type_name.to_sym, rule_element) : []
        end

        # Builds a rule path based on context (repeated items or map keys/values)
        def build_rule_path(type_name, rule_element)
          if @for_map
            build_map_rule_path(type_name, rule_element)
          else
            build_item_rule_path(type_name, rule_element)
          end
        end

        # Builds a rule path for map keys/values: map.<keys|values>.<type>.<rule>
        def build_map_rule_path(type_name, rule_element)
          # Field numbers from validate.proto
          map_field = 19  # map field in FieldConstraints
          keys_field = 4  # keys field in MapRules
          values_field = 5  # values field in MapRules

          # Type field numbers in FieldConstraints
          type_field_numbers = {
            int32: 3, int64: 4, sint32: 7, sint64: 8, sfixed32: 11, sfixed64: 12,
            uint32: 5, uint64: 6, fixed32: 9, fixed64: 10,
            float: 1, double: 2, string: 14, bytes: 15, bool: 13, enum: 16
          }

          # Rule field numbers within type-specific rules
          numeric_rule_numbers = {
            const: 1, lt: 2, lte: 3, gt: 4, gte: 5, in: 6, not_in: 7
          }

          type_field = type_field_numbers[type_name] || 0
          rule_field = numeric_rule_numbers[rule_element] || 0

          # Determine field type for the rule element
          rule_field_type = case rule_element
                            when :const, :lt, :lte, :gt, :gte then type_name
                            when :in, :not_in then type_name
                            else :message
                            end

          part_field = @map_part == :keys ? keys_field : values_field
          part_name = @map_part == :keys ? "keys" : "values"

          # Build elements in reverse order (finalize_violations will reverse)
          [
            FieldPathElement.new(
              field_number: rule_field,
              field_name: rule_element.to_s,
              field_type: rule_field_type
            ),
            FieldPathElement.new(
              field_number: type_field,
              field_name: type_name.to_s,
              field_type: :message
            ),
            FieldPathElement.new(
              field_number: part_field,
              field_name: part_name,
              field_type: :message
            ),
            FieldPathElement.new(
              field_number: map_field,
              field_name: "map",
              field_type: :message
            )
          ]
        end

        # Builds a rule path for item-level rules: repeated.items.<type>.<rule>
        def build_item_rule_path(type_name, rule_element)
          # Field numbers from validate.proto
          repeated_field = 18  # repeated field in FieldConstraints
          items_field = 4      # items field in RepeatedRules

          # Type field numbers in FieldConstraints (for the items constraint)
          type_field_numbers = {
            int32: 3, int64: 4, sint32: 7, sint64: 8, sfixed32: 11, sfixed64: 12,
            uint32: 5, uint64: 6, fixed32: 9, fixed64: 10,
            float: 1, double: 2, string: 14, bytes: 15, bool: 13, enum: 16
          }

          # Rule field numbers within type-specific rules
          numeric_rule_numbers = {
            const: 1, lt: 2, lte: 3, gt: 4, gte: 5, in: 6, not_in: 7
          }

          type_field = type_field_numbers[type_name] || 0
          rule_field = numeric_rule_numbers[rule_element] || 0

          # Determine field type for the rule element
          rule_field_type = case rule_element
                            when :const then type_name
                            when :lt, :lte, :gt, :gte then type_name
                            when :in, :not_in then type_name
                            else :message
                            end

          # Build elements in reverse order (finalize_violations will reverse)
          # So we want: [gt, int32, items, repeated] which becomes [repeated, items, int32, gt]
          [
            FieldPathElement.new(
              field_number: rule_field,
              field_name: rule_element.to_s,
              field_type: rule_field_type
            ),
            FieldPathElement.new(
              field_number: type_field,
              field_name: type_name.to_s,
              field_type: :message
            ),
            FieldPathElement.new(
              field_number: items_field,
              field_name: "items",
              field_type: :message
            ),
            FieldPathElement.new(
              field_number: repeated_field,
              field_name: "repeated",
              field_type: :message
            )
          ]
        end

        def validate_item(context, value)
          return if context.done?
          return if should_ignore_item?(value)
          return if check_value(value)

          violation = Violation.new(
            constraint_id: @constraint_id,
            message: @message,
            rule_path: @rule_path
          )
          violation.field_value = value
          context.add(violation)
        end

        protected

        def check_value(_value)
          raise NotImplementedError, "Subclasses must implement #check_value"
        end

        private

        def should_ignore_item?(value)
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
          when FalseClass then true
          when TrueClass then false
          when Array then value.empty?
          when Hash then value.empty?
          else
            false
          end
        end
      end

      # Item numeric greater than
      class ItemNumericGtRule < ItemRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gt",
            message: "value must be greater than #{bound}",
            type_name: type_name,
            rule_element: :gt,
            for_map: for_map,
            map_part: map_part
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value > @bound
        end
      end

      # Item numeric greater than or equal
      class ItemNumericGteRule < ItemRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.gte",
            message: "value must be greater than or equal to #{bound}",
            type_name: type_name,
            rule_element: :gte,
            for_map: for_map,
            map_part: map_part
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value >= @bound
        end
      end

      # Item numeric less than
      class ItemNumericLtRule < ItemRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.lt",
            message: "value must be less than #{bound}",
            type_name: type_name,
            rule_element: :lt,
            for_map: for_map,
            map_part: map_part
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value < @bound
        end
      end

      # Item numeric less than or equal
      class ItemNumericLteRule < ItemRule
        def initialize(field:, bound:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.lte",
            message: "value must be less than or equal to #{bound}",
            type_name: type_name,
            rule_element: :lte,
            for_map: for_map,
            map_part: map_part
          )
          @bound = bound
        end

        protected

        def check_value(value)
          value <= @bound
        end
      end

      # Item numeric const
      class ItemNumericConstRule < ItemRule
        def initialize(field:, const:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.const",
            message: "value must equal #{const}",
            type_name: type_name,
            rule_element: :const,
            for_map: for_map,
            map_part: map_part
          )
          @const = const
        end

        protected

        def check_value(value)
          value == @const
        end
      end

      # Item numeric in
      class ItemNumericInRule < ItemRule
        def initialize(field:, allowed:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.in",
            message: "value must be in #{allowed.inspect}",
            type_name: type_name,
            rule_element: :in,
            for_map: for_map,
            map_part: map_part
          )
          @allowed = allowed
        end

        protected

        def check_value(value)
          @allowed.include?(value)
        end
      end

      # Item numeric not_in
      class ItemNumericNotInRule < ItemRule
        def initialize(field:, disallowed:, type_name:, ignore: :IGNORE_UNSPECIFIED, for_map: false, map_part: nil)
          super(
            field: field,
            ignore: ignore,
            constraint_id: "#{type_name}.not_in",
            message: "value must not be in #{disallowed.inspect}",
            type_name: type_name,
            rule_element: :not_in,
            for_map: for_map,
            map_part: map_part
          )
          @disallowed = disallowed
        end

        protected

        def check_value(value)
          !@disallowed.include?(value)
        end
      end

      # Item CEL rule - validates items using CEL expressions
      class ItemCelRule < Base
        def initialize(field:, program:, constraint_id:, message:, ignore: :IGNORE_UNSPECIFIED)
          super()
          @field = field
          @program = program
          @constraint_id = constraint_id
          @message = message
          @ignore = ignore
        end

        def validate_item(context, value)
          return if context.done?
          return if should_ignore_item?(value)

          activation = { this: CelHelpers.ruby_to_cel(value), now: Time.now }
          result = @program.evaluate(activation)

          unless result == true || (result.respond_to?(:value) && result.value == true)
            violation = Violation.new(
              constraint_id: @constraint_id,
              message: @message
            )
            violation.field_value = value
            context.add(violation)
          end
        rescue Cel::EvaluateError => e
          raise RuntimeError.new("CEL evaluation failed for item: #{e.message}", cause: e)
        end

        private

        def should_ignore_item?(value)
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
          when FalseClass then true
          when TrueClass then false
          when Array then value.empty?
          when Hash then value.empty?
          else
            false
          end
        end
      end
    end
  end
end
