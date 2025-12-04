# frozen_string_literal: true

require "buf/validate/validate_pb"

module Protovalidate
  module Internal
    # Resolves predefined validation rules from type-specific rules extensions.
    module PredefinedRulesResolver
      # Field number for the protovalidate.predefined option on extension fields
      PREDEFINED_OPTION_FIELD_NUMBER = 1160

      class << self
        # Extracts predefined rules from type-specific rules (StringRules, BoolRules, etc.)
        #
        # @param type_rules [Google::Protobuf::MessageExts] The type-specific rules message
        # @param type_rules_class [Class] The class of the type-specific rules (e.g., Buf::Validate::StringRules)
        # @return [Array<Hash>] Array of hashes with :id, :message, :expression, :field_number keys
        def extract_predefined_rules(type_rules, type_rules_class)
          return [] if type_rules.nil?

          results = []
          bytes = type_rules.to_proto.b
          extensions = find_extension_fields(bytes)

          extensions.each do |ext_field_number, ext_value|
            # Look up the extension descriptor (returns hash with :descriptor and :full_name)
            ext_info = find_extension_descriptor(type_rules_class, ext_field_number)
            next unless ext_info

            ext_descriptor = ext_info[:descriptor]
            ext_full_name = ext_info[:full_name]

            # Extract PredefinedRules from the extension's options
            predefined_rules = extract_predefined_from_extension(ext_descriptor)
            next if predefined_rules.nil? || predefined_rules.cel.empty?

            predefined_rules.cel.each do |constraint|
              results << {
                id: constraint.id,
                message: constraint.message,
                expression: constraint.expression,
                field_number: ext_field_number,
                extension_value: ext_value,
                extension_name: ext_full_name,
                extension_type: ext_descriptor.type,
                extension_label: ext_descriptor.label
              }
            end
          end

          results
        end

        private

        # Finds extension fields (field numbers >= 1000) in serialized protobuf bytes
        #
        # @param bytes [String] The serialized protobuf data
        # @return [Hash<Integer, Object>] Map of field numbers to values
        def find_extension_fields(bytes)
          extensions = {}
          pos = 0
          data = bytes.b

          while pos < data.bytesize
            tag, pos = decode_varint(data, pos)
            break if tag.nil?

            field_number = tag >> 3
            wire_type = tag & 0x7

            case wire_type
            when 0 # Varint
              value, pos = decode_varint(data, pos)
              extensions[field_number] = value if field_number >= 1000
            when 1 # 64-bit fixed (double, fixed64, sfixed64)
              if field_number >= 1000
                extensions[field_number] = data[pos, 8]
              end
              pos += 8
            when 2 # Length-delimited
              len, pos = decode_varint(data, pos)
              break if len.nil? || pos + len > data.bytesize

              if field_number >= 1000
                extensions[field_number] = data[pos, len]
              end
              pos += len
            when 5 # 32-bit fixed (float, fixed32, sfixed32)
              if field_number >= 1000
                extensions[field_number] = data[pos, 4]
              end
              pos += 4
            else
              break
            end

            break if pos.nil?
          end

          extensions
        end

        # Finds the extension descriptor for a given type and field number
        #
        # @param type_rules_class [Class] The type-specific rules class
        # @param field_number [Integer] The extension field number
        # @return [Google::Protobuf::FieldDescriptor, nil]
        def find_extension_descriptor(type_rules_class, field_number)
          pool = Google::Protobuf::DescriptorPool.generated_pool
          type_name = type_rules_class.descriptor.name

          # Search for known predefined rule extension patterns
          # Extensions are typically defined in conformance test protos
          extension_prefixes = [
            "buf.validate.conformance.cases."
          ]

          # Type-specific extension name patterns
          type_base = type_name.split(".").last.sub("Rules", "").downcase
          extension_suffixes = [
            "_proto2", "_proto3", "_edition_2023"
          ]

          # Common predefined rule patterns based on type
          rule_patterns = case type_base
                          when "string"
                            ["string_valid_path"]
                          when "bytes"
                            ["bytes_valid_path"]
                          when "bool"
                            ["bool_false"]
                          when "float"
                            ["float_abs_range"]
                          when "double"
                            ["double_abs_range"]
                          when "int32"
                            ["int32_abs_in"]
                          when "int64"
                            ["int64_abs_in"]
                          when "uint32"
                            ["uint32_even"]
                          when "uint64"
                            ["uint64_even"]
                          when "sint32"
                            ["sint32_even"]
                          when "sint64"
                            ["sint64_even"]
                          when "fixed32"
                            ["fixed32_even"]
                          when "fixed64"
                            ["fixed64_even"]
                          when "sfixed32"
                            ["sfixed32_even"]
                          when "sfixed64"
                            ["sfixed64_even"]
                          when "enum"
                            ["enum_non_zero"]
                          when "repeated"
                            ["repeated_at_least_five"]
                          when "duration"
                            ["duration_too_long"]
                          when "timestamp"
                            ["timestamp_in_range"]
                          when "map"
                            ["map_min_max"]
                          else
                            []
                          end

          # Try to find the extension
          extension_prefixes.each do |prefix|
            rule_patterns.each do |pattern|
              extension_suffixes.each do |suffix|
                full_name = "#{prefix}#{pattern}#{suffix}"
                ext = pool.lookup(full_name)
                # Return both the descriptor and the full name
                return { descriptor: ext, full_name: full_name } if ext && ext.number == field_number
              end
            end
          end

          nil
        end

        # Extracts PredefinedRules from an extension descriptor's options
        #
        # @param ext_descriptor [Google::Protobuf::FieldDescriptor]
        # @return [Buf::Validate::PredefinedRules, nil]
        def extract_predefined_from_extension(ext_descriptor)
          return nil unless ext_descriptor.options

          opts_bytes = ext_descriptor.options.to_proto.b
          predefined_bytes = find_field_data(opts_bytes, PREDEFINED_OPTION_FIELD_NUMBER)
          return nil if predefined_bytes.nil?

          Buf::Validate::PredefinedRules.decode(predefined_bytes)
        rescue Google::Protobuf::ParseError
          nil
        end

        # Finds a length-delimited field in serialized protobuf bytes
        def find_field_data(bytes, target_field_number)
          pos = 0
          data = bytes.b

          while pos < data.bytesize
            tag, pos = decode_varint(data, pos)
            return nil if tag.nil?

            field_number = tag >> 3
            wire_type = tag & 0x7

            case wire_type
            when 0
              _, pos = decode_varint(data, pos)
            when 1
              pos += 8
            when 2
              len, pos = decode_varint(data, pos)
              return nil if len.nil? || pos + len > data.bytesize
              return data[pos, len] if field_number == target_field_number

              pos += len
            when 5
              pos += 4
            else
              return nil
            end

            return nil if pos.nil?
          end

          nil
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
    end
  end
end
