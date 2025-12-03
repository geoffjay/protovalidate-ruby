# frozen_string_literal: true

require "cel"
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
          return @cache[full_name] if @cache.key?(full_name)

          begin
            rules = compile_rules(descriptor)
            @cache[full_name] = rules
            rules
          rescue StandardError => e
            # Cache compilation errors to avoid retrying
            @cache[full_name] = e
            raise CompilationError.new("Failed to compile rules for #{full_name}", cause: e)
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
          field_rules = compile_field_rules(field)
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

      def compile_field_rules(field)
        rules = []

        constraint = ConstraintResolver.resolve_field_constraints(field)
        return rules if constraint.nil?

        # Handle ignore conditions
        ignore = constraint.ignore || :IGNORE_UNSPECIFIED

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
            ignore: ignore
          )
        end

        # Type-specific rules
        type_rules = compile_type_specific_rules(field, constraint, ignore)
        rules.concat(type_rules)

        rules
      end

      def compile_type_specific_rules(field, constraint, ignore)
        rules = []

        case field.type
        when :string
          rules.concat(compile_string_rules(field, constraint.string, ignore)) if constraint.string
        when :bytes
          rules.concat(compile_bytes_rules(field, constraint.bytes, ignore)) if constraint.bytes
        when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64
          rules.concat(compile_int_rules(field, constraint, ignore))
        when :uint32, :uint64, :fixed32, :fixed64
          rules.concat(compile_uint_rules(field, constraint, ignore))
        when :float, :double
          rules.concat(compile_float_rules(field, constraint, ignore))
        when :bool
          rules.concat(compile_bool_rules(field, constraint.bool, ignore)) if constraint.bool
        when :enum
          rules.concat(compile_enum_rules(field, constraint.enum, ignore)) if constraint.enum
        when :message
          rules.concat(compile_message_field_rules(field, constraint, ignore))
        end

        # Handle repeated fields
        if field.label == :repeated && !field.map? && constraint.repeated
          rules.concat(compile_repeated_rules(field, constraint.repeated, ignore))
        end

        # Handle map fields
        rules.concat(compile_map_rules(field, constraint.map, ignore)) if field.map? && constraint.map

        rules
      end

      def compile_string_rules(field, string_rules, ignore)
        rules = []

        # Standard string validations compiled to CEL
        if string_rules.min_len&.positive?
          rules << build_cel_rule(field, "size(this) >= #{string_rules.min_len}", ignore,
                                  "string.min_len", "value length must be at least #{string_rules.min_len} characters")
        end

        if string_rules.max_len&.positive?
          rules << build_cel_rule(field, "size(this) <= #{string_rules.max_len}", ignore,
                                  "string.max_len", "value length must be at most #{string_rules.max_len} characters")
        end

        if string_rules.len&.positive?
          rules << build_cel_rule(field, "size(this) == #{string_rules.len}", ignore,
                                  "string.len", "value length must be #{string_rules.len} characters")
        end

        if string_rules.pattern && !string_rules.pattern.empty?
          escaped = string_rules.pattern.gsub("\\", "\\\\\\\\").gsub('"', '\\"')
          rules << build_cel_rule(field, "this.matches(\"#{escaped}\")", ignore,
                                  "string.pattern", "value must match pattern '#{string_rules.pattern}'")
        end

        # Well-known string formats
        if string_rules.email
          rules << build_cel_rule(field, "this.isEmail()", ignore,
                                  "string.email", "value must be a valid email address")
        end

        if string_rules.uri
          rules << build_cel_rule(field, "this.isUri()", ignore,
                                  "string.uri", "value must be a valid URI")
        end

        if string_rules.uri_ref
          rules << build_cel_rule(field, "this.isUriRef()", ignore,
                                  "string.uri_ref", "value must be a valid URI reference")
        end

        if string_rules.hostname
          rules << build_cel_rule(field, "this.isHostname()", ignore,
                                  "string.hostname", "value must be a valid hostname")
        end

        if string_rules.ip
          rules << build_cel_rule(field, "this.isIp()", ignore,
                                  "string.ip", "value must be a valid IP address")
        end

        if string_rules.ipv4
          rules << build_cel_rule(field, "this.isIp(4)", ignore,
                                  "string.ipv4", "value must be a valid IPv4 address")
        end

        if string_rules.ipv6
          rules << build_cel_rule(field, "this.isIp(6)", ignore,
                                  "string.ipv6", "value must be a valid IPv6 address")
        end

        # UUID validation
        if string_rules.uuid
          uuid_pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
          rules << build_cel_rule(field, "this.matches(\"#{uuid_pattern}\")", ignore,
                                  "string.uuid", "value must be a valid UUID")
        end

        rules.compact
      end

      def compile_bytes_rules(field, bytes_rules, ignore)
        rules = []

        if bytes_rules.min_len&.positive?
          rules << build_cel_rule(field, "size(this) >= #{bytes_rules.min_len}", ignore,
                                  "bytes.min_len", "value length must be at least #{bytes_rules.min_len} bytes")
        end

        if bytes_rules.max_len&.positive?
          rules << build_cel_rule(field, "size(this) <= #{bytes_rules.max_len}", ignore,
                                  "bytes.max_len", "value length must be at most #{bytes_rules.max_len} bytes")
        end

        if bytes_rules.len&.positive?
          rules << build_cel_rule(field, "size(this) == #{bytes_rules.len}", ignore,
                                  "bytes.len", "value length must be #{bytes_rules.len} bytes")
        end

        rules.compact
      end

      def compile_int_rules(field, constraint, ignore)
        rules = []
        int_rules = case field.type
                    when :int32, :sint32, :sfixed32 then constraint.int32
                    when :int64, :sint64, :sfixed64 then constraint.int64
                    end
        return rules unless int_rules

        type_name = field.type.to_s

        if int_rules.gt
          rules << build_cel_rule(field, "this > #{int_rules.gt}", ignore,
                                  "#{type_name}.gt", "value must be greater than #{int_rules.gt}")
        end

        if int_rules.gte
          rules << build_cel_rule(field, "this >= #{int_rules.gte}", ignore,
                                  "#{type_name}.gte", "value must be greater than or equal to #{int_rules.gte}")
        end

        if int_rules.lt
          rules << build_cel_rule(field, "this < #{int_rules.lt}", ignore,
                                  "#{type_name}.lt", "value must be less than #{int_rules.lt}")
        end

        if int_rules.lte
          rules << build_cel_rule(field, "this <= #{int_rules.lte}", ignore,
                                  "#{type_name}.lte", "value must be less than or equal to #{int_rules.lte}")
        end

        if int_rules.const
          rules << build_cel_rule(field, "this == #{int_rules.const}", ignore,
                                  "#{type_name}.const", "value must equal #{int_rules.const}")
        end

        if int_rules.in && !int_rules.in.empty?
          in_list = int_rules.in.join(", ")
          rules << build_cel_rule(field, "this in [#{in_list}]", ignore,
                                  "#{type_name}.in", "value must be in [#{in_list}]")
        end

        if int_rules.not_in && !int_rules.not_in.empty?
          not_in_list = int_rules.not_in.join(", ")
          rules << build_cel_rule(field, "!(this in [#{not_in_list}])", ignore,
                                  "#{type_name}.not_in", "value must not be in [#{not_in_list}]")
        end

        rules.compact
      end

      def compile_uint_rules(field, constraint, ignore)
        rules = []
        uint_rules = case field.type
                     when :uint32, :fixed32 then constraint.uint32
                     when :uint64, :fixed64 then constraint.uint64
                     end
        return rules unless uint_rules

        type_name = field.type.to_s

        if uint_rules.gt
          rules << build_cel_rule(field, "this > uint(#{uint_rules.gt})", ignore,
                                  "#{type_name}.gt", "value must be greater than #{uint_rules.gt}")
        end

        if uint_rules.gte
          rules << build_cel_rule(field, "this >= uint(#{uint_rules.gte})", ignore,
                                  "#{type_name}.gte", "value must be greater than or equal to #{uint_rules.gte}")
        end

        if uint_rules.lt
          rules << build_cel_rule(field, "this < uint(#{uint_rules.lt})", ignore,
                                  "#{type_name}.lt", "value must be less than #{uint_rules.lt}")
        end

        if uint_rules.lte
          rules << build_cel_rule(field, "this <= uint(#{uint_rules.lte})", ignore,
                                  "#{type_name}.lte", "value must be less than or equal to #{uint_rules.lte}")
        end

        rules.compact
      end

      def compile_float_rules(field, constraint, ignore)
        rules = []
        float_rules = case field.type
                      when :float then constraint.float
                      when :double then constraint.double
                      end
        return rules unless float_rules

        type_name = field.type.to_s

        if float_rules.gt
          rules << build_cel_rule(field, "this > #{float_rules.gt}", ignore,
                                  "#{type_name}.gt", "value must be greater than #{float_rules.gt}")
        end

        if float_rules.gte
          rules << build_cel_rule(field, "this >= #{float_rules.gte}", ignore,
                                  "#{type_name}.gte", "value must be greater than or equal to #{float_rules.gte}")
        end

        if float_rules.lt
          rules << build_cel_rule(field, "this < #{float_rules.lt}", ignore,
                                  "#{type_name}.lt", "value must be less than #{float_rules.lt}")
        end

        if float_rules.lte
          rules << build_cel_rule(field, "this <= #{float_rules.lte}", ignore,
                                  "#{type_name}.lte", "value must be less than or equal to #{float_rules.lte}")
        end

        rules.compact
      end

      def compile_bool_rules(field, bool_rules, ignore)
        rules = []

        unless bool_rules.const.nil?
          rules << build_cel_rule(field, "this == #{bool_rules.const}", ignore,
                                  "bool.const", "value must be #{bool_rules.const}")
        end

        rules.compact
      end

      def compile_enum_rules(field, enum_rules, ignore)
        rules = []

        if enum_rules.defined_only
          rules << Rules::EnumDefinedOnlyRule.new(
            field: field,
            ignore: ignore
          )
        end

        if enum_rules.in && !enum_rules.in.empty?
          in_list = enum_rules.in.join(", ")
          rules << build_cel_rule(field, "int(this) in [#{in_list}]", ignore,
                                  "enum.in", "value must be in [#{in_list}]")
        end

        if enum_rules.not_in && !enum_rules.not_in.empty?
          not_in_list = enum_rules.not_in.join(", ")
          rules << build_cel_rule(field, "!(int(this) in [#{not_in_list}])", ignore,
                                  "enum.not_in", "value must not be in [#{not_in_list}]")
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
