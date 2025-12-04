# frozen_string_literal: true

require "cel"
require "ostruct"
require_relative "rules"
require_relative "cel_helpers"
require_relative "constraint_resolver"
require_relative "predefined_rules_resolver"

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
        # Disable type checking because we can't declare the type of 'this'
        # which varies per field (scalar, repeated, message, etc.)
        Cel::Environment.new(
          declarations: CelHelpers.declarations,
          disable_check: true
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
        constraint.cel.each_with_index do |cel_rule, cel_index|
          program = compile_cel_expression(cel_rule.expression, field.subtype || field, :field)
          rules << Rules::FieldCelRule.new(
            field: field,
            program: program,
            rule: cel_rule,
            cel_env: @cel_env,
            ignore: ignore,
            oneof_name: oneof_name,
            cel_index: cel_index
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
          # Only add SubMessageRule for singular message fields (not repeated, not map)
          # Repeated message validation is handled by RepeatedItemsRule.validate_item
          unless is_map || field.label == :repeated
            rules.concat(compile_message_field_rules(field, constraint, ignore))
          end
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

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, string_rules, Buf::Validate::StringRules, ignore))

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
        rules << Rules::StringTuuidRule.new(field: field, ignore: ignore) if string_rules.tuuid
        rules << Rules::StringAddressRule.new(field: field, ignore: ignore) if string_rules.address
        rules << Rules::StringHostAndPortRule.new(field: field, port_required: true, ignore: ignore) if string_rules.host_and_port

        # IP with prefix length rules
        rules << Rules::StringIpWithPrefixlenRule.new(field: field, version: 0, ignore: ignore) if string_rules.ip_with_prefixlen
        rules << Rules::StringIpWithPrefixlenRule.new(field: field, version: 4, ignore: ignore) if string_rules.ipv4_with_prefixlen
        rules << Rules::StringIpWithPrefixlenRule.new(field: field, version: 6, ignore: ignore) if string_rules.ipv6_with_prefixlen

        # IP prefix rules (network address)
        rules << Rules::StringIpPrefixRule.new(field: field, version: 0, ignore: ignore) if string_rules.ip_prefix
        rules << Rules::StringIpPrefixRule.new(field: field, version: 4, ignore: ignore) if string_rules.ipv4_prefix
        rules << Rules::StringIpPrefixRule.new(field: field, version: 6, ignore: ignore) if string_rules.ipv6_prefix

        # Well-known regex patterns
        if string_rules.well_known_regex && string_rules.well_known_regex != :KNOWN_REGEX_UNSPECIFIED
          # strict defaults to true if not explicitly set
          strict_value = string_rules.has_strict? ? string_rules.strict : true
          rules << Rules::StringWellKnownRegexRule.new(
            field: field,
            regex_type: string_rules.well_known_regex,
            strict: strict_value,
            ignore: ignore
          )
        end

        rules
      end

      def compile_bytes_rules(field, bytes_rules, ignore, _oneof_name = nil)
        rules = []

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, bytes_rules, Buf::Validate::BytesRules, ignore))

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
        int_rules, rules_class = case field.type
                                 when :int32 then [constraint.int32, Buf::Validate::Int32Rules]
                                 when :int64 then [constraint.int64, Buf::Validate::Int64Rules]
                                 when :sint32 then [constraint.sint32, Buf::Validate::SInt32Rules]
                                 when :sint64 then [constraint.sint64, Buf::Validate::SInt64Rules]
                                 when :sfixed32 then [constraint.sfixed32, Buf::Validate::SFixed32Rules]
                                 when :sfixed64 then [constraint.sfixed64, Buf::Validate::SFixed64Rules]
                                 else [nil, nil]
                                 end
        return rules unless int_rules

        type_name = field.type.to_s

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, int_rules, rules_class, ignore))

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
        uint_rules, rules_class = case field.type
                                  when :uint32 then [constraint.uint32, Buf::Validate::UInt32Rules]
                                  when :uint64 then [constraint.uint64, Buf::Validate::UInt64Rules]
                                  when :fixed32 then [constraint.fixed32, Buf::Validate::Fixed32Rules]
                                  when :fixed64 then [constraint.fixed64, Buf::Validate::Fixed64Rules]
                                  else [nil, nil]
                                  end
        return rules unless uint_rules

        type_name = field.type.to_s

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, uint_rules, rules_class, ignore))

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
        float_rules, rules_class = case field.type
                                   when :float then [constraint.float, Buf::Validate::FloatRules]
                                   when :double then [constraint.double, Buf::Validate::DoubleRules]
                                   else [nil, nil]
                                   end
        return rules unless float_rules

        type_name = field.type.to_s

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, float_rules, rules_class, ignore))

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

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, bool_rules, Buf::Validate::BoolRules, ignore))

        if bool_rules.has_const?
          rules << Rules::BoolConstRule.new(field: field, const: bool_rules.const, ignore: ignore, oneof_name: oneof_name)
        end

        rules
      end

      def compile_enum_rules(field, enum_rules, ignore, _oneof_name = nil)
        rules = []

        # Compile predefined rules from extensions
        rules.concat(compile_predefined_rules(field, enum_rules, Buf::Validate::EnumRules, ignore))

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

      # Maps wrapper type names to their corresponding constraint field and rules class
      WRAPPER_TYPE_INFO = {
        "google.protobuf.StringValue" => { constraint_field: :string, rules_class: Buf::Validate::StringRules },
        "google.protobuf.BytesValue" => { constraint_field: :bytes, rules_class: Buf::Validate::BytesRules },
        "google.protobuf.BoolValue" => { constraint_field: :bool, rules_class: Buf::Validate::BoolRules },
        "google.protobuf.Int32Value" => { constraint_field: :int32, rules_class: Buf::Validate::Int32Rules },
        "google.protobuf.Int64Value" => { constraint_field: :int64, rules_class: Buf::Validate::Int64Rules },
        "google.protobuf.UInt32Value" => { constraint_field: :uint32, rules_class: Buf::Validate::UInt32Rules },
        "google.protobuf.UInt64Value" => { constraint_field: :uint64, rules_class: Buf::Validate::UInt64Rules },
        "google.protobuf.FloatValue" => { constraint_field: :float, rules_class: Buf::Validate::FloatRules },
        "google.protobuf.DoubleValue" => { constraint_field: :double, rules_class: Buf::Validate::DoubleRules }
      }.freeze

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
            # Check for wrapper types
            wrapper_info = WRAPPER_TYPE_INFO[wkt_name]
            if wrapper_info
              type_rules = constraint.send(wrapper_info[:constraint_field])
              if type_rules
                rules.concat(compile_wrapper_predefined_rules(field, type_rules, wrapper_info[:rules_class], ignore))
              end
            else
              # Nested message validation
              rules << Rules::SubMessageRule.new(field: field, factory: self)
            end
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
          # Compile item-level rules for scalar types
          item_rules = compile_item_rules(field, repeated_rules.items, ignore)
          rules << Rules::RepeatedItemsRule.new(
            field: field,
            item_constraints: repeated_rules.items,
            factory: self,
            ignore: ignore,
            item_rules: item_rules
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

        # Get map entry key/value field descriptors
        value_field = nil
        key_field = nil
        if field.subtype
          field.subtype.each do |subfield|
            value_field = subfield if subfield.name == "value"
            key_field = subfield if subfield.name == "key"
          end
        end

        # Get key and value types for field path elements
        key_type = key_field&.type
        value_type = value_field&.type

        # Key and value rules
        if map_rules.keys && key_field
          key_rules = compile_map_key_rules(key_field, map_rules.keys, ignore)
          rules << Rules::MapKeysRule.new(
            field: field,
            key_constraints: map_rules.keys,
            factory: self,
            ignore: ignore,
            key_rules: key_rules,
            key_type: key_type,
            value_type: value_type
          )
        end

        if map_rules.values && value_field
          value_rules = compile_map_value_rules(value_field, map_rules.values, ignore)
          rules << Rules::MapValuesRule.new(
            field: field,
            value_constraints: map_rules.values,
            factory: self,
            ignore: ignore,
            value_rules: value_rules,
            key_type: key_type,
            value_type: value_type
          )
        end

        rules.compact
      end

      # Compiles rules for validating map values
      def compile_map_value_rules(value_field, value_constraints, _parent_ignore)
        rules = []

        # Use the value constraint's ignore
        value_ignore = value_constraints.ignore

        # Get the type of values in the map
        value_type = value_field.type

        case value_type
        when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64
          rules.concat(compile_int_value_rules(value_field, value_constraints, value_ignore))
        when :uint32, :uint64, :fixed32, :fixed64
          rules.concat(compile_uint_value_rules(value_field, value_constraints, value_ignore))
        when :float, :double
          rules.concat(compile_float_value_rules(value_field, value_constraints, value_ignore))
        when :string
          rules.concat(compile_string_value_rules(value_field, value_constraints.string, value_ignore)) if value_constraints.string
        when :bytes
          rules.concat(compile_bytes_value_rules(value_field, value_constraints.bytes, value_ignore)) if value_constraints.bytes
        when :bool
          rules.concat(compile_bool_value_rules(value_field, value_constraints.bool, value_ignore)) if value_constraints.bool
        when :enum
          rules.concat(compile_enum_value_rules(value_field, value_constraints.enum, value_ignore)) if value_constraints.enum
        end

        # Handle CEL rules on values
        if value_constraints.cel && !value_constraints.cel.empty?
          value_constraints.cel.each_with_index do |cel_rule, idx|
            rules << build_item_cel_rule(value_field, cel_rule.expression, value_ignore,
                                         cel_rule.id || "cel[#{idx}]",
                                         cel_rule.message || "CEL expression evaluated to false")
          end
        end

        rules.compact
      end

      # Compile map value rules for int types
      def compile_int_value_rules(value_field, constraint, ignore, for_map: true, map_part: :values)
        rules = []
        type_name = value_field.type.to_s

        # Look for the numeric rules in the constraint
        numeric_rules = constraint.send(type_name) rescue nil
        return rules unless numeric_rules

        if numeric_rules.has_const?
          rules << Rules::ItemNumericConstRule.new(field: value_field, const: numeric_rules.const, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        case numeric_rules.less_than
        when :lt
          rules << Rules::ItemNumericLtRule.new(field: value_field, bound: numeric_rules.lt, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        when :lte
          rules << Rules::ItemNumericLteRule.new(field: value_field, bound: numeric_rules.lte, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        case numeric_rules.greater_than
        when :gt
          rules << Rules::ItemNumericGtRule.new(field: value_field, bound: numeric_rules.gt, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        when :gte
          rules << Rules::ItemNumericGteRule.new(field: value_field, bound: numeric_rules.gte, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        if numeric_rules.in && !numeric_rules.in.empty?
          rules << Rules::ItemNumericInRule.new(field: value_field, allowed: numeric_rules.in.to_a, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        if numeric_rules.not_in && !numeric_rules.not_in.empty?
          rules << Rules::ItemNumericNotInRule.new(field: value_field, disallowed: numeric_rules.not_in.to_a, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        rules
      end

      def compile_uint_value_rules(value_field, constraint, ignore, for_map: true, map_part: :values)
        compile_int_value_rules(value_field, constraint, ignore, for_map: for_map, map_part: map_part)
      end

      def compile_float_value_rules(value_field, constraint, ignore, for_map: true, map_part: :values)
        rules = []
        type_name = value_field.type.to_s

        numeric_rules = constraint.send(type_name) rescue nil
        return rules unless numeric_rules

        if numeric_rules.has_const?
          rules << Rules::ItemNumericConstRule.new(field: value_field, const: numeric_rules.const, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        case numeric_rules.less_than
        when :lt
          rules << Rules::ItemNumericLtRule.new(field: value_field, bound: numeric_rules.lt, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        when :lte
          rules << Rules::ItemNumericLteRule.new(field: value_field, bound: numeric_rules.lte, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        case numeric_rules.greater_than
        when :gt
          rules << Rules::ItemNumericGtRule.new(field: value_field, bound: numeric_rules.gt, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        when :gte
          rules << Rules::ItemNumericGteRule.new(field: value_field, bound: numeric_rules.gte, type_name: type_name, ignore: ignore, for_map: for_map, map_part: map_part)
        end

        rules
      end

      def compile_string_value_rules(_field, _string_rules, _ignore)
        # TODO: Implement string value rules
        []
      end

      def compile_bytes_value_rules(_field, _bytes_rules, _ignore)
        # TODO: Implement bytes value rules
        []
      end

      def compile_bool_value_rules(_field, _bool_rules, _ignore)
        # TODO: Implement bool value rules
        []
      end

      def compile_enum_value_rules(_field, _enum_rules, _ignore)
        # TODO: Implement enum value rules
        []
      end

      # Compile map key rules
      def compile_map_key_rules(key_field, key_constraints, _parent_ignore)
        # Similar to value rules but for keys
        # Keys can only be integral types or strings
        rules = []
        key_ignore = key_constraints.ignore

        case key_field.type
        when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64
          rules.concat(compile_int_value_rules(key_field, key_constraints, key_ignore, for_map: true, map_part: :keys))
        when :uint32, :uint64, :fixed32, :fixed64
          rules.concat(compile_uint_value_rules(key_field, key_constraints, key_ignore, for_map: true, map_part: :keys))
        when :string
          rules.concat(compile_string_value_rules(key_field, key_constraints.string, key_ignore)) if key_constraints.string
        when :bool
          rules.concat(compile_bool_value_rules(key_field, key_constraints.bool, key_ignore)) if key_constraints.bool
        end

        rules.compact
      end

      # Compiles rules for validating individual items in a repeated field
      def compile_item_rules(field, item_constraints, _parent_ignore)
        rules = []

        # Use the item constraint's ignore, not the parent's
        item_ignore = item_constraints.ignore

        # Get the type of items in the repeated field
        item_type = field.type

        case item_type
        when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64
          rules.concat(compile_int_item_rules(field, item_constraints, item_ignore))
        when :uint32, :uint64, :fixed32, :fixed64
          rules.concat(compile_uint_item_rules(field, item_constraints, item_ignore))
        when :float, :double
          rules.concat(compile_float_item_rules(field, item_constraints, item_ignore))
        when :string
          rules.concat(compile_string_item_rules(field, item_constraints.string, item_ignore)) if item_constraints.string
        when :bytes
          rules.concat(compile_bytes_item_rules(field, item_constraints.bytes, item_ignore)) if item_constraints.bytes
        when :bool
          rules.concat(compile_bool_item_rules(field, item_constraints.bool, item_ignore)) if item_constraints.bool
        when :enum
          rules.concat(compile_enum_item_rules(field, item_constraints.enum, item_ignore)) if item_constraints.enum
        when :message
          # Handle wrapper types in repeated fields
          if field.subtype
            wrapper_info = WRAPPER_TYPE_INFO[field.subtype.name]
            if wrapper_info
              type_rules = item_constraints.send(wrapper_info[:constraint_field])
              if type_rules
                rules.concat(compile_wrapper_item_predefined_rules(field, type_rules, wrapper_info[:rules_class], item_ignore))
              end
            end
          end
        end

        # Handle CEL rules on items
        if item_constraints.cel && !item_constraints.cel.empty?
          item_constraints.cel.each_with_index do |cel_rule, idx|
            rules << build_item_cel_rule(field, cel_rule.expression, item_ignore,
                                         cel_rule.id || "cel[#{idx}]",
                                         cel_rule.message || "CEL expression evaluated to false")
          end
        end

        rules.compact
      end

      def compile_int_item_rules(field, constraint, ignore)
        rules = []
        type_name = numeric_type_for(field.type)

        # Look for the numeric rules in the constraint
        numeric_rules = constraint.send(type_name) rescue nil
        return rules unless numeric_rules

        if numeric_rules.has_const?
          rules << Rules::ItemNumericConstRule.new(field: field, const: numeric_rules.const, type_name: type_name, ignore: ignore)
        end

        case numeric_rules.less_than
        when :lt
          rules << Rules::ItemNumericLtRule.new(field: field, bound: numeric_rules.lt, type_name: type_name, ignore: ignore)
        when :lte
          rules << Rules::ItemNumericLteRule.new(field: field, bound: numeric_rules.lte, type_name: type_name, ignore: ignore)
        end

        case numeric_rules.greater_than
        when :gt
          rules << Rules::ItemNumericGtRule.new(field: field, bound: numeric_rules.gt, type_name: type_name, ignore: ignore)
        when :gte
          rules << Rules::ItemNumericGteRule.new(field: field, bound: numeric_rules.gte, type_name: type_name, ignore: ignore)
        end

        if numeric_rules.in && !numeric_rules.in.empty?
          rules << Rules::ItemNumericInRule.new(field: field, allowed: numeric_rules.in.to_a, type_name: type_name, ignore: ignore)
        end

        if numeric_rules.not_in && !numeric_rules.not_in.empty?
          rules << Rules::ItemNumericNotInRule.new(field: field, disallowed: numeric_rules.not_in.to_a, type_name: type_name, ignore: ignore)
        end

        rules
      end

      def compile_uint_item_rules(field, constraint, ignore)
        compile_int_item_rules(field, constraint, ignore)
      end

      def compile_float_item_rules(field, constraint, ignore)
        rules = []
        type_name = numeric_type_for(field.type)

        # Look for the numeric rules in the constraint
        numeric_rules = constraint.send(type_name) rescue nil
        return rules unless numeric_rules

        if numeric_rules.has_const?
          rules << Rules::ItemNumericConstRule.new(field: field, const: numeric_rules.const, type_name: type_name, ignore: ignore)
        end

        case numeric_rules.less_than
        when :lt
          rules << Rules::ItemNumericLtRule.new(field: field, bound: numeric_rules.lt, type_name: type_name, ignore: ignore)
        when :lte
          rules << Rules::ItemNumericLteRule.new(field: field, bound: numeric_rules.lte, type_name: type_name, ignore: ignore)
        end

        case numeric_rules.greater_than
        when :gt
          rules << Rules::ItemNumericGtRule.new(field: field, bound: numeric_rules.gt, type_name: type_name, ignore: ignore)
        when :gte
          rules << Rules::ItemNumericGteRule.new(field: field, bound: numeric_rules.gte, type_name: type_name, ignore: ignore)
        end

        if numeric_rules.in && !numeric_rules.in.empty?
          rules << Rules::ItemNumericInRule.new(field: field, allowed: numeric_rules.in.to_a, type_name: type_name, ignore: ignore)
        end

        if numeric_rules.not_in && !numeric_rules.not_in.empty?
          rules << Rules::ItemNumericNotInRule.new(field: field, disallowed: numeric_rules.not_in.to_a, type_name: type_name, ignore: ignore)
        end

        rules
      end

      def compile_string_item_rules(_field, _string_rules, _ignore)
        # TODO: Implement string item rules
        []
      end

      def compile_bytes_item_rules(_field, _bytes_rules, _ignore)
        # TODO: Implement bytes item rules
        []
      end

      def compile_bool_item_rules(_field, _bool_rules, _ignore)
        # TODO: Implement bool item rules
        []
      end

      def compile_enum_item_rules(_field, _enum_rules, _ignore)
        # TODO: Implement enum item rules
        []
      end

      # Compiles predefined rules for items in a repeated wrapper field
      #
      # @param field [Google::Protobuf::FieldDescriptor] The repeated wrapper field descriptor
      # @param type_rules [Google::Protobuf::MessageExts] The type-specific rules (StringRules, BoolRules, etc.)
      # @param rules_class [Class] The class of the type-specific rules
      # @param ignore [Symbol] The ignore condition
      # @return [Array<Rules::Base>] The compiled item rules
      def compile_wrapper_item_predefined_rules(field, type_rules, rules_class, ignore)
        return [] if type_rules.nil? || rules_class.nil?

        predefined = PredefinedRulesResolver.extract_predefined_rules(type_rules, rules_class)
        return [] if predefined.empty?

        type_rules_info = TYPE_RULES_FIELD_INFO[rules_class.name] || { field_number: 0, field_name: "" }

        predefined.map do |rule_info|
          build_wrapper_item_predefined_cel_rule(
            field,
            rule_info[:expression],
            ignore,
            rule_info[:id],
            rule_info[:message],
            rule_info[:field_number],
            rule_info[:extension_name],
            type_rules_info,
            rule_info[:extension_value],
            rule_info[:extension_type],
            rule_info[:extension_label]
          )
        end.compact
      end

      # Builds a CEL rule for a predefined rule on a wrapper item in a repeated field
      def build_wrapper_item_predefined_cel_rule(field, expression, ignore, constraint_id, message, field_number, extension_name, type_rules_info, extension_value = nil, extension_type = nil, extension_label = nil)
        program = compile_cel_expression(expression, field, :field)
        rule = OpenStruct.new(
          id: constraint_id,
          message: message,
          expression: expression
        )

        Rules::WrapperItemPredefinedCelRule.new(
          field: field,
          program: program,
          rule: rule,
          cel_env: @cel_env,
          ignore: ignore,
          field_number: field_number,
          extension_name: extension_name,
          type_rules_field_number: type_rules_info[:field_number],
          type_rules_field_name: type_rules_info[:field_name],
          extension_value: extension_value,
          extension_type: extension_type,
          extension_label: extension_label
        )
      rescue StandardError => e
        raise CompilationError.new("Failed to compile wrapper item predefined CEL expression '#{expression}': #{e.message}", cause: e)
      end

      # Compiles predefined rules for wrapper types (StringValue, Int32Value, etc.)
      #
      # @param field [Google::Protobuf::FieldDescriptor] The wrapper field descriptor
      # @param type_rules [Google::Protobuf::MessageExts] The type-specific rules (StringRules, BoolRules, etc.)
      # @param rules_class [Class] The class of the type-specific rules
      # @param ignore [Symbol] The ignore condition
      # @return [Array<Rules::Base>] The compiled rules
      def compile_wrapper_predefined_rules(field, type_rules, rules_class, ignore)
        return [] if type_rules.nil? || rules_class.nil?

        predefined = PredefinedRulesResolver.extract_predefined_rules(type_rules, rules_class)
        return [] if predefined.empty?

        type_rules_info = TYPE_RULES_FIELD_INFO[rules_class.name] || { field_number: 0, field_name: "" }

        predefined.map do |rule_info|
          build_wrapper_predefined_cel_rule(
            field,
            rule_info[:expression],
            ignore,
            rule_info[:id],
            rule_info[:message],
            rule_info[:field_number],
            rule_info[:extension_name],
            type_rules_info,
            rule_info[:extension_value],
            rule_info[:extension_type],
            rule_info[:extension_label]
          )
        end.compact
      end

      # Builds a CEL rule for a predefined rule on a wrapper type
      def build_wrapper_predefined_cel_rule(field, expression, ignore, constraint_id, message, field_number, extension_name, type_rules_info, extension_value = nil, extension_type = nil, extension_label = nil)
        program = compile_cel_expression(expression, field, :field)
        rule = OpenStruct.new(
          id: constraint_id,
          message: message,
          expression: expression
        )

        Rules::WrapperPredefinedCelRule.new(
          field: field,
          program: program,
          rule: rule,
          cel_env: @cel_env,
          ignore: ignore,
          field_number: field_number,
          extension_name: extension_name,
          type_rules_field_number: type_rules_info[:field_number],
          type_rules_field_name: type_rules_info[:field_name],
          extension_value: extension_value,
          extension_type: extension_type,
          extension_label: extension_label
        )
      rescue StandardError => e
        raise CompilationError.new("Failed to compile wrapper predefined CEL expression '#{expression}': #{e.message}", cause: e)
      end

      # Compiles predefined rules from type-specific rules extensions
      #
      # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
      # @param type_rules [Google::Protobuf::MessageExts] The type-specific rules (StringRules, BoolRules, etc.)
      # @param rules_class [Class] The class of the type-specific rules
      # @param ignore [Symbol] The ignore condition
      # @return [Array<Rules::Base>] The compiled rules
      # Mapping of rules class to the field info in FieldConstraints
      TYPE_RULES_FIELD_INFO = {
        "Buf::Validate::FloatRules" => { field_number: 1, field_name: "float" },
        "Buf::Validate::DoubleRules" => { field_number: 2, field_name: "double" },
        "Buf::Validate::Int32Rules" => { field_number: 3, field_name: "int32" },
        "Buf::Validate::Int64Rules" => { field_number: 4, field_name: "int64" },
        "Buf::Validate::UInt32Rules" => { field_number: 5, field_name: "uint32" },
        "Buf::Validate::UInt64Rules" => { field_number: 6, field_name: "uint64" },
        "Buf::Validate::SInt32Rules" => { field_number: 7, field_name: "sint32" },
        "Buf::Validate::SInt64Rules" => { field_number: 8, field_name: "sint64" },
        "Buf::Validate::Fixed32Rules" => { field_number: 9, field_name: "fixed32" },
        "Buf::Validate::Fixed64Rules" => { field_number: 10, field_name: "fixed64" },
        "Buf::Validate::SFixed32Rules" => { field_number: 11, field_name: "sfixed32" },
        "Buf::Validate::SFixed64Rules" => { field_number: 12, field_name: "sfixed64" },
        "Buf::Validate::BoolRules" => { field_number: 13, field_name: "bool" },
        "Buf::Validate::StringRules" => { field_number: 14, field_name: "string" },
        "Buf::Validate::BytesRules" => { field_number: 15, field_name: "bytes" },
        "Buf::Validate::EnumRules" => { field_number: 16, field_name: "enum" },
        "Buf::Validate::RepeatedRules" => { field_number: 18, field_name: "repeated" },
        "Buf::Validate::MapRules" => { field_number: 19, field_name: "map" },
        "Buf::Validate::AnyRules" => { field_number: 20, field_name: "any" },
        "Buf::Validate::DurationRules" => { field_number: 21, field_name: "duration" },
        "Buf::Validate::TimestampRules" => { field_number: 22, field_name: "timestamp" }
      }.freeze

      def compile_predefined_rules(field, type_rules, rules_class, ignore)
        return [] if type_rules.nil? || rules_class.nil?

        predefined = PredefinedRulesResolver.extract_predefined_rules(type_rules, rules_class)
        return [] if predefined.empty?

        type_rules_info = TYPE_RULES_FIELD_INFO[rules_class.name] || { field_number: 0, field_name: "" }

        predefined.map do |rule_info|
          build_predefined_cel_rule(
            field,
            rule_info[:expression],
            ignore,
            rule_info[:id],
            rule_info[:message],
            rule_info[:field_number],
            rule_info[:extension_name],
            type_rules_info,
            rule_info[:extension_value],
            rule_info[:extension_type],
            rule_info[:extension_label]
          )
        end.compact
      end

      # Builds a CEL rule for a predefined rule expression
      def build_predefined_cel_rule(field, expression, ignore, constraint_id, message, field_number, extension_name, type_rules_info, extension_value = nil, extension_type = nil, extension_label = nil)
        program = compile_cel_expression(expression, field, :field)
        rule = OpenStruct.new(
          id: constraint_id,
          message: message,
          expression: expression
        )

        Rules::PredefinedCelRule.new(
          field: field,
          program: program,
          rule: rule,
          cel_env: @cel_env,
          ignore: ignore,
          field_number: field_number,
          extension_name: extension_name,
          type_rules_field_number: type_rules_info[:field_number],
          type_rules_field_name: type_rules_info[:field_name],
          extension_value: extension_value,
          extension_type: extension_type,
          extension_label: extension_label
        )
      rescue StandardError => e
        raise CompilationError.new("Failed to compile predefined CEL expression '#{expression}': #{e.message}", cause: e)
      end

      def build_item_cel_rule(field, expression, ignore, constraint_id, message)
        program = compile_cel_expression(expression, field, :field)
        Rules::ItemCelRule.new(
          field: field,
          program: program,
          constraint_id: constraint_id,
          message: message,
          ignore: ignore
        )
      rescue StandardError => e
        raise CompilationError.new("Failed to compile item CEL expression '#{expression}': #{e.message}", cause: e)
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

      def numeric_type_for(type_name)
        # Return the actual field type, not the wire type
        type_name
      end
    end
  end
end
