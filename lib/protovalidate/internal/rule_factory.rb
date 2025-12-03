# frozen_string_literal: true

require "cel"
require "ostruct"
require_relative "rules"
require_relative "cel_helpers"
require_relative "constraint_resolver"

module Protovalidate
  module Internal
    # Factory for creating and caching validation rules.
    # Compiles rules from protobuf descriptors on first access.
    class RuleFactory
      def initialize
        @cache = {}
        @cache_mutex = Mutex.new
        @cel_env = build_cel_environment
      end

      # Gets validation rules for a message descriptor.
      # Returns cached rules if available, otherwise compiles and caches them.
      #
      # @param descriptor [Google::Protobuf::Descriptor] The message descriptor
      # @return [Array<Rules::Base>] The compiled rules
      def get(descriptor)
        full_name = descriptor.name

        @cache_mutex.synchronize do
          if @cache.key?(full_name)
            cached = @cache[full_name]
            # Re-raise cached compilation errors
            raise cached if cached.is_a?(Exception)

            return cached
          end

          begin
            rules = compile_rules(descriptor)
            @cache[full_name] = rules
            rules
          rescue StandardError => e
            # Cache compilation errors to avoid retrying
            error = CompilationError.new("Failed to compile rules for #{full_name}", cause: e)
            @cache[full_name] = error
            raise error
          end
        end
      end

      private

      def build_cel_environment
        # Build a CEL environment with protovalidate functions
        Cel::Environment.new(
          declarations: CelHelpers.declarations
        )
      end

      def compile_rules(descriptor)
        rules = []

        # Build a map of field name -> oneof name for implicit ignore handling (protobuf oneofs)
        oneof_map = {}
        descriptor.each_oneof do |oneof|
          oneof.each do |field|
            oneof_map[field.name] = oneof.name
          end
        end

        # Also track fields that are part of message-level oneof constraints
        # These fields should have implicit IGNORE_IF_UNPOPULATED behavior
        message_oneof_fields = Set.new
        message_constraint = ConstraintResolver.resolve_message_constraints(descriptor)
        if message_constraint&.respond_to?(:oneof) && message_constraint.oneof
          message_constraint.oneof.each do |oneof_rule|
            oneof_rule.fields.each { |f| message_oneof_fields << f }
          end
        end

        # Compile message-level rules
        message_rules = compile_message_rules(descriptor)
        rules.concat(message_rules)

        # Compile oneof rules
        descriptor.each_oneof do |oneof|
          oneof_rules = compile_oneof_rules(oneof)
          rules.concat(oneof_rules)
        end

        # Compile field rules
        descriptor.each do |field|
          field_rules = compile_field_rules(field, oneof_map, message_oneof_fields)
          rules.concat(field_rules)
        end

        rules
      end

      def compile_message_rules(descriptor)
        rules = []

        constraint = ConstraintResolver.resolve_message_constraints(descriptor)
        return rules unless constraint

        # Compile message-level CEL expressions
        constraint.cel.each do |cel_rule|
          program = compile_cel_expression(cel_rule.expression, descriptor, :message)
          rules << Rules::CelRule.new(
            program: program,
            rule: cel_rule,
            cel_env: @cel_env
          )
        end

        # Compile message-level oneof rules
        if constraint.respond_to?(:oneof) && constraint.oneof
          constraint.oneof.each do |oneof_rule|
            # Validate that all fields exist
            fields = oneof_rule.fields.to_a
            fields.each do |field_name|
              found = false
              descriptor.each do |field|
                if field.name == field_name
                  found = true
                  break
                end
              end
              unless found
                raise CompilationError.new("field #{field_name} not found in message #{descriptor.name}")
              end
            end

            # Validate at least one field is specified
            if fields.empty?
              raise CompilationError.new("at least one field must be specified in oneof rule for the message #{descriptor.name}")
            end

            # Check for duplicate fields across all oneof rules
            # (we validate this per-rule for now)

            rules << Rules::MessageOneofRule.new(
              fields: fields,
              required: oneof_rule.required,
              descriptor: descriptor
            )
          end
        end

        rules
      end

      def compile_oneof_rules(oneof)
        rules = []

        constraint = ConstraintResolver.resolve_oneof_constraints(oneof)
        return rules unless constraint

        if constraint.required
          rules << Rules::OneofRequiredRule.new(
            oneof: oneof,
            constraint: constraint
          )
        end

        rules
      end

      def compile_field_rules(field, oneof_map = {}, message_oneof_fields = Set.new)
        rules = []

        constraint = ConstraintResolver.resolve_field_constraints(field)
        return rules if constraint.nil?

        # Handle ignore conditions
        ignore = constraint.ignore || :IGNORE_UNSPECIFIED

        # For fields that are part of a message-level oneof, apply implicit ignore
        # unless they have an explicit ignore setting
        if message_oneof_fields.include?(field.name) && ignore == :IGNORE_UNSPECIFIED
          ignore = :IGNORE_IF_UNPOPULATED
        end

        # Check if field belongs to a protobuf oneof (use the map passed from compile_rules)
        oneof_name = oneof_map[field.name]

        # Required constraint
        if constraint.required
          rules << Rules::RequiredRule.new(
            field: field,
            ignore: ignore
          )
        end

        # Field-level CEL expressions
        constraint.cel.each do |cel_rule|
          program = compile_cel_expression(cel_rule.expression, field.subtype || field, :field)
          rules << Rules::FieldCelRule.new(
            field: field,
            program: program,
            rule: cel_rule,
            cel_env: @cel_env,
            ignore: ignore,
            oneof_name: oneof_name
          )
        end

        # Type-specific rules
        type_rules = compile_type_specific_rules(field, constraint, ignore, oneof_name)
        rules.concat(type_rules)

        rules
      end

      def compile_type_specific_rules(field, constraint, ignore, oneof_name = nil)
        rules = []
        is_map = map_field?(field)

        case field.type
        when :string
          rules.concat(compile_string_rules(field, constraint.string, ignore, oneof_name)) if constraint.string
        when :bytes
          rules.concat(compile_bytes_rules(field, constraint.bytes, ignore, oneof_name)) if constraint.bytes
        when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64
          rules.concat(compile_int_rules(field, constraint, ignore, oneof_name))
        when :uint32, :uint64, :fixed32, :fixed64
          rules.concat(compile_uint_rules(field, constraint, ignore, oneof_name))
        when :float, :double
          rules.concat(compile_float_rules(field, constraint, ignore, oneof_name))
        when :bool
          rules.concat(compile_bool_rules(field, constraint.bool, ignore, oneof_name)) if constraint.bool
        when :enum
          rules.concat(compile_enum_rules(field, constraint.enum, ignore, oneof_name)) if constraint.enum
        when :message
          rules.concat(compile_message_field_rules(field, constraint, ignore)) unless is_map
        end

        # Handle repeated fields (but not maps, which are also repeated)
        if field.label == :repeated && !is_map && constraint.repeated
          rules.concat(compile_repeated_rules(field, constraint.repeated, ignore))
        end

        # Handle map fields
        rules.concat(compile_map_rules(field, constraint.map, ignore)) if is_map && constraint.map

        rules
      end

      # Checks if a field is a map field.
      # In protobuf, maps are represented as repeated message fields with an entry type
      # containing "key" and "value" fields.
      def map_field?(field)
        return false unless field.type == :message && field.label == :repeated
        return false unless field.subtype

        # Map entry types have exactly 2 fields: "key" (field number 1) and "value" (field number 2)
        has_key = false
        has_value = false

        field.subtype.each do |subfield|
          has_key = true if subfield.name == "key" && subfield.number == 1
          has_value = true if subfield.name == "value" && subfield.number == 2
        end

        has_key && has_value
      end

      def compile_string_rules(field, string_rules, ignore, _oneof_name = nil)
        rules = []

        # Const
        if string_rules.has_const?
          rules << Rules::StringConstRule.new(field: field, const: string_rules.const, ignore: ignore)
        end

        # Length (unicode codepoints)
        if string_rules.has_len?
          rules << Rules::StringLenRule.new(field: field, len: string_rules.len, ignore: ignore)
        end

        if string_rules.has_min_len?
          rules << Rules::StringMinLenRule.new(field: field, min_len: string_rules.min_len, ignore: ignore)
        end

        if string_rules.has_max_len?
          rules << Rules::StringMaxLenRule.new(field: field, max_len: string_rules.max_len, ignore: ignore)
        end

        # Byte length
        if string_rules.has_len_bytes?
          rules << Rules::StringLenBytesRule.new(field: field, len_bytes: string_rules.len_bytes, ignore: ignore)
        end

        if string_rules.has_min_bytes?
          rules << Rules::StringMinBytesRule.new(field: field, min_bytes: string_rules.min_bytes, ignore: ignore)
        end

        if string_rules.has_max_bytes?
          rules << Rules::StringMaxBytesRule.new(field: field, max_bytes: string_rules.max_bytes, ignore: ignore)
        end

        # Pattern
        if string_rules.pattern && !string_rules.pattern.empty?
          rules << Rules::StringPatternRule.new(field: field, pattern: string_rules.pattern, ignore: ignore)
        end

        # Prefix/Suffix/Contains
        if string_rules.prefix && !string_rules.prefix.empty?
          rules << Rules::StringPrefixRule.new(field: field, prefix: string_rules.prefix, ignore: ignore)
        end

        if string_rules.suffix && !string_rules.suffix.empty?
          rules << Rules::StringSuffixRule.new(field: field, suffix: string_rules.suffix, ignore: ignore)
        end

        if string_rules.contains && !string_rules.contains.empty?
          rules << Rules::StringContainsRule.new(field: field, contains: string_rules.contains, ignore: ignore)
        end

        if string_rules.not_contains && !string_rules.not_contains.empty?
          rules << Rules::StringNotContainsRule.new(field: field, not_contains: string_rules.not_contains, ignore: ignore)
        end

        # In/NotIn lists
        if string_rules.in && !string_rules.in.empty?
          rules << Rules::StringInRule.new(field: field, values: string_rules.in.to_a, ignore: ignore)
        end

        if string_rules.not_in && !string_rules.not_in.empty?
          rules << Rules::StringNotInRule.new(field: field, values: string_rules.not_in.to_a, ignore: ignore)
        end

        # Well-known formats
        rules << Rules::StringEmailRule.new(field: field, ignore: ignore) if string_rules.email
        rules << Rules::StringHostnameRule.new(field: field, ignore: ignore) if string_rules.hostname
        rules << Rules::StringIpRule.new(field: field, version: 0, ignore: ignore) if string_rules.ip
        rules << Rules::StringIpRule.new(field: field, version: 4, ignore: ignore) if string_rules.ipv4
        rules << Rules::StringIpRule.new(field: field, version: 6, ignore: ignore) if string_rules.ipv6
        rules << Rules::StringUriRule.new(field: field, ignore: ignore) if string_rules.uri
        rules << Rules::StringUriRefRule.new(field: field, ignore: ignore) if string_rules.uri_ref
        rules << Rules::StringUuidRule.new(field: field, ignore: ignore) if string_rules.uuid

        rules
      end

      def compile_bytes_rules(field, bytes_rules, ignore, _oneof_name = nil)
        rules = []

        # Const
        if bytes_rules.has_const?
          rules << Rules::BytesConstRule.new(field: field, const: bytes_rules.const, ignore: ignore)
        end

        # Length
        if bytes_rules.has_len?
          rules << Rules::BytesLenRule.new(field: field, len: bytes_rules.len, ignore: ignore)
        end

        if bytes_rules.has_min_len?
          rules << Rules::BytesMinLenRule.new(field: field, min_len: bytes_rules.min_len, ignore: ignore)
        end

        if bytes_rules.has_max_len?
          rules << Rules::BytesMaxLenRule.new(field: field, max_len: bytes_rules.max_len, ignore: ignore)
        end

        # Pattern
        if bytes_rules.pattern && !bytes_rules.pattern.empty?
          rules << Rules::BytesPatternRule.new(field: field, pattern: bytes_rules.pattern, ignore: ignore)
        end

        # Prefix/Suffix/Contains
        if bytes_rules.prefix && !bytes_rules.prefix.empty?
          rules << Rules::BytesPrefixRule.new(field: field, prefix: bytes_rules.prefix, ignore: ignore)
        end

        if bytes_rules.suffix && !bytes_rules.suffix.empty?
          rules << Rules::BytesSuffixRule.new(field: field, suffix: bytes_rules.suffix, ignore: ignore)
        end

        if bytes_rules.contains && !bytes_rules.contains.empty?
          rules << Rules::BytesContainsRule.new(field: field, contains: bytes_rules.contains, ignore: ignore)
        end

        # In/NotIn lists
        if bytes_rules.in && !bytes_rules.in.empty?
          rules << Rules::BytesInRule.new(field: field, values: bytes_rules.in.to_a, ignore: ignore)
        end

        if bytes_rules.not_in && !bytes_rules.not_in.empty?
          rules << Rules::BytesNotInRule.new(field: field, values: bytes_rules.not_in.to_a, ignore: ignore)
        end

        # IP address formats
        rules << Rules::BytesIpRule.new(field: field, version: 0, ignore: ignore) if bytes_rules.ip
        rules << Rules::BytesIpRule.new(field: field, version: 4, ignore: ignore) if bytes_rules.ipv4
        rules << Rules::BytesIpRule.new(field: field, version: 6, ignore: ignore) if bytes_rules.ipv6

        rules
      end

      # Compiles numeric range rules, handling combined gt/lt/gte/lte bounds.
      # Returns a combined rule when both lower and upper bounds are set,
      # or individual rules when only one bound is set.
      def compile_numeric_range_rules(field, num_rules, ignore, type_name, _oneof_name = nil)
        rules = []

        has_gt = num_rules.has_gt?
        has_gte = num_rules.has_gte?
        has_lt = num_rules.has_lt?
        has_lte = num_rules.has_lte?

        # Determine if we have a combined range
        lower_strict = has_gt
        lower_inclusive = has_gte
        upper_strict = has_lt
        upper_inclusive = has_lte

        lower = lower_strict ? num_rules.gt : (lower_inclusive ? num_rules.gte : nil)
        upper = upper_strict ? num_rules.lt : (upper_inclusive ? num_rules.lte : nil)

        if lower && upper
          # Combined range rule
          # Inclusive (inside range): lower < upper
          # Exclusive (outside range): lower > upper
          exclusive = lower > upper

          if lower_strict && upper_strict
            if exclusive
              rules << Rules::NumericGtLtExclusiveRule.new(field: field, gt: lower, lt: upper, type_name: type_name, ignore: ignore)
            else
              rules << Rules::NumericGtLtRule.new(field: field, gt: lower, lt: upper, type_name: type_name, ignore: ignore)
            end
          elsif lower_strict && upper_inclusive
            if exclusive
              rules << Rules::NumericGtLteExclusiveRule.new(field: field, gt: lower, lte: upper, type_name: type_name, ignore: ignore)
            else
              rules << Rules::NumericGtLteRule.new(field: field, gt: lower, lte: upper, type_name: type_name, ignore: ignore)
            end
          elsif lower_inclusive && upper_strict
            if exclusive
              rules << Rules::NumericGteLtExclusiveRule.new(field: field, gte: lower, lt: upper, type_name: type_name, ignore: ignore)
            else
              rules << Rules::NumericGteLtRule.new(field: field, gte: lower, lt: upper, type_name: type_name, ignore: ignore)
            end
          else # lower_inclusive && upper_inclusive
            if exclusive
              rules << Rules::NumericGteLteExclusiveRule.new(field: field, gte: lower, lte: upper, type_name: type_name, ignore: ignore)
            else
              rules << Rules::NumericGteLteRule.new(field: field, gte: lower, lte: upper, type_name: type_name, ignore: ignore)
            end
          end
        else
          # Single bound rules
          if has_gt
            rules << Rules::NumericGtRule.new(field: field, bound: num_rules.gt, ignore: ignore, type_name: type_name)
          end

          if has_gte
            rules << Rules::NumericGteRule.new(field: field, bound: num_rules.gte, ignore: ignore, type_name: type_name)
          end

          if has_lt
            rules << Rules::NumericLtRule.new(field: field, bound: num_rules.lt, ignore: ignore, type_name: type_name)
          end

          if has_lte
            rules << Rules::NumericLteRule.new(field: field, bound: num_rules.lte, ignore: ignore, type_name: type_name)
          end
        end

        rules
      end

      def compile_int_rules(field, constraint, ignore, oneof_name = nil)
        rules = []
        int_rules = case field.type
                    when :int32 then constraint.int32
                    when :int64 then constraint.int64
                    when :sint32 then constraint.sint32
                    when :sint64 then constraint.sint64
                    when :sfixed32 then constraint.sfixed32
                    when :sfixed64 then constraint.sfixed64
                    end
        return rules unless int_rules

        type_name = field.type.to_s

        # Handle combined range rules
        rules.concat(compile_numeric_range_rules(field, int_rules, ignore, type_name, oneof_name))

        if int_rules.has_const?
          rules << Rules::NumericConstRule.new(field: field, const: int_rules.const, ignore: ignore,
                                               type_name: type_name)
        end

        if int_rules.in && !int_rules.in.empty?
          rules << Rules::NumericInRule.new(field: field, values: int_rules.in.to_a, ignore: ignore,
                                            type_name: type_name)
        end

        if int_rules.not_in && !int_rules.not_in.empty?
          rules << Rules::NumericNotInRule.new(field: field, values: int_rules.not_in.to_a, ignore: ignore,
                                               type_name: type_name)
        end

        rules
      end

      def compile_uint_rules(field, constraint, ignore, oneof_name = nil)
        rules = []
        uint_rules = case field.type
                     when :uint32 then constraint.uint32
                     when :uint64 then constraint.uint64
                     when :fixed32 then constraint.fixed32
                     when :fixed64 then constraint.fixed64
                     end
        return rules unless uint_rules

        type_name = field.type.to_s

        # Handle combined range rules
        rules.concat(compile_numeric_range_rules(field, uint_rules, ignore, type_name, oneof_name))

        if uint_rules.has_const?
          rules << Rules::NumericConstRule.new(field: field, const: uint_rules.const, ignore: ignore,
                                               type_name: type_name)
        end

        if uint_rules.in && !uint_rules.in.empty?
          rules << Rules::NumericInRule.new(field: field, values: uint_rules.in.to_a, ignore: ignore,
                                            type_name: type_name)
        end

        if uint_rules.not_in && !uint_rules.not_in.empty?
          rules << Rules::NumericNotInRule.new(field: field, values: uint_rules.not_in.to_a, ignore: ignore,
                                               type_name: type_name)
        end

        rules
      end

      def compile_float_rules(field, constraint, ignore, oneof_name = nil)
        rules = []
        float_rules = case field.type
                      when :float then constraint.float
                      when :double then constraint.double
                      end
        return rules unless float_rules

        type_name = field.type.to_s

        # Handle combined range rules
        rules.concat(compile_numeric_range_rules(field, float_rules, ignore, type_name, oneof_name))

        if float_rules.has_const?
          rules << Rules::NumericConstRule.new(field: field, const: float_rules.const, ignore: ignore,
                                               type_name: type_name)
        end

        if float_rules.in && !float_rules.in.empty?
          rules << Rules::NumericInRule.new(field: field, values: float_rules.in.to_a, ignore: ignore,
                                            type_name: type_name)
        end

        if float_rules.not_in && !float_rules.not_in.empty?
          rules << Rules::NumericNotInRule.new(field: field, values: float_rules.not_in.to_a, ignore: ignore,
                                               type_name: type_name)
        end

        rules << Rules::FloatFiniteRule.new(field: field, ignore: ignore, type_name: type_name) if float_rules.finite

        rules
      end

      def compile_bool_rules(field, bool_rules, ignore, oneof_name = nil)
        rules = []

        if bool_rules.has_const?
          rules << Rules::BoolConstRule.new(field: field, const: bool_rules.const, ignore: ignore, oneof_name: oneof_name)
        end

        rules
      end

      def compile_enum_rules(field, enum_rules, ignore, _oneof_name = nil)
        rules = []

        # const rule
        if enum_rules.respond_to?(:has_const?) && enum_rules.has_const?
          rules << Rules::EnumConstRule.new(
            field: field,
            const_value: enum_rules.const,
            ignore: ignore
          )
        end

        if enum_rules.defined_only
          rules << Rules::EnumDefinedOnlyRule.new(
            field: field,
            ignore: ignore
          )
        end

        if enum_rules.in && !enum_rules.in.empty?
          rules << Rules::EnumInRule.new(
            field: field,
            in_list: enum_rules.in.to_a,
            ignore: ignore
          )
        end

        if enum_rules.not_in && !enum_rules.not_in.empty?
          rules << Rules::EnumNotInRule.new(
            field: field,
            not_in_list: enum_rules.not_in.to_a,
            ignore: ignore
          )
        end

        rules.compact
      end

      def compile_message_field_rules(field, constraint, ignore)
        rules = []

        # Handle well-known types
        if field.subtype
          wkt_name = field.subtype.name
          case wkt_name
          when "google.protobuf.Any"
            rules.concat(compile_any_rules(field, constraint.any, ignore)) if constraint.any
          when "google.protobuf.Duration"
            rules.concat(compile_duration_rules(field, constraint.duration, ignore)) if constraint.duration
          when "google.protobuf.Timestamp"
            rules.concat(compile_timestamp_rules(field, constraint.timestamp, ignore)) if constraint.timestamp
          else
            # Nested message validation
            rules << Rules::SubMessageRule.new(field: field, factory: self)
          end
        else
          # Nested message validation
          rules << Rules::SubMessageRule.new(field: field, factory: self)
        end

        rules
      end

      def compile_any_rules(field, any_rules, ignore)
        rules = []

        if any_rules.in && !any_rules.in.empty?
          rules << Rules::AnyInRule.new(
            field: field,
            type_urls: any_rules.in,
            ignore: ignore
          )
        end

        if any_rules.not_in && !any_rules.not_in.empty?
          rules << Rules::AnyNotInRule.new(
            field: field,
            type_urls: any_rules.not_in,
            ignore: ignore
          )
        end

        rules
      end

      def compile_duration_rules(_field, _duration_rules, _ignore)
        []
        # Duration validation rules would be compiled here
        # For now, return empty - to be implemented
      end

      def compile_timestamp_rules(_field, _timestamp_rules, _ignore)
        []
        # Timestamp validation rules would be compiled here
        # For now, return empty - to be implemented
      end

      def compile_repeated_rules(field, repeated_rules, ignore)
        rules = []

        if repeated_rules.min_items&.positive?
          rules << build_cel_rule(field, "size(this) >= #{repeated_rules.min_items}", ignore,
                                  "repeated.min_items", "value must contain at least #{repeated_rules.min_items} items")
        end

        if repeated_rules.max_items&.positive?
          rules << build_cel_rule(field, "size(this) <= #{repeated_rules.max_items}", ignore,
                                  "repeated.max_items", "value must contain at most #{repeated_rules.max_items} items")
        end

        if repeated_rules.unique
          rules << build_cel_rule(field, "this.unique()", ignore,
                                  "repeated.unique", "value must contain unique items")
        end

        # Item-level rules would be applied to each element
        if repeated_rules.items
          rules << Rules::RepeatedItemsRule.new(
            field: field,
            item_constraints: repeated_rules.items,
            factory: self,
            ignore: ignore
          )
        end

        rules.compact
      end

      def compile_map_rules(field, map_rules, ignore)
        rules = []

        if map_rules.min_pairs&.positive?
          rules << build_cel_rule(field, "size(this) >= #{map_rules.min_pairs}", ignore,
                                  "map.min_pairs", "value must contain at least #{map_rules.min_pairs} pairs")
        end

        if map_rules.max_pairs&.positive?
          rules << build_cel_rule(field, "size(this) <= #{map_rules.max_pairs}", ignore,
                                  "map.max_pairs", "value must contain at most #{map_rules.max_pairs} pairs")
        end

        # Key and value rules
        if map_rules.keys
          rules << Rules::MapKeysRule.new(
            field: field,
            key_constraints: map_rules.keys,
            factory: self,
            ignore: ignore
          )
        end

        if map_rules.values
          rules << Rules::MapValuesRule.new(
            field: field,
            value_constraints: map_rules.values,
            factory: self,
            ignore: ignore
          )
        end

        rules.compact
      end

      def build_cel_rule(field, expression, ignore, constraint_id, message)
        program = compile_cel_expression(expression, field, :field)
        rule = OpenStruct.new(
          id: constraint_id,
          message: message,
          expression: expression
        )

        Rules::FieldCelRule.new(
          field: field,
          program: program,
          rule: rule,
          cel_env: @cel_env,
          ignore: ignore
        )
      rescue StandardError => e
        raise CompilationError.new("Failed to compile CEL expression '#{expression}': #{e.message}", cause: e)
      end

      def compile_cel_expression(expression, _context, _type)
        @cel_env.program(expression)
      rescue Cel::ParseError, Cel::CheckError => e
        raise CompilationError.new("Invalid CEL expression '#{expression}': #{e.message}", cause: e)
      end
    end
  end
end
