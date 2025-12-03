# frozen_string_literal: true

module Protovalidate
  module Internal
    # Resolves validation constraints from protobuf descriptors.
    # Reads the buf.validate extensions to extract validation rules.
    module ConstraintResolver
      # Extension field number for buf.validate extensions
      # All three extensions (field, message, oneof) use the same number 1159
      EXTENSION_FIELD_NUMBER = 1159

      class << self
        # Resolves message-level validation constraints.
        #
        # @param descriptor [Google::Protobuf::Descriptor] The message descriptor
        # @return [Buf::Validate::MessageRules, nil] The message constraints or nil
        def resolve_message_constraints(descriptor)
          return nil unless descriptor.options

          extract_extension(
            descriptor.options,
            EXTENSION_FIELD_NUMBER,
            Buf::Validate::MessageRules
          )
        end

        # Resolves field-level validation constraints.
        #
        # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
        # @return [Buf::Validate::FieldRules, nil] The field constraints or nil
        def resolve_field_constraints(field)
          return nil unless field.options

          extract_extension(
            field.options,
            EXTENSION_FIELD_NUMBER,
            Buf::Validate::FieldRules
          )
        end

        # Resolves oneof-level validation constraints.
        #
        # @param oneof [Google::Protobuf::OneofDescriptor] The oneof descriptor
        # @return [Buf::Validate::OneofRules, nil] The oneof constraints or nil
        def resolve_oneof_constraints(oneof)
          return nil unless oneof.options

          extract_extension(
            oneof.options,
            EXTENSION_FIELD_NUMBER,
            Buf::Validate::OneofRules
          )
        end

        # Resolves predefined validation rules.
        #
        # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
        # @return [Buf::Validate::PredefinedRules, nil] The predefined constraints or nil
        def resolve_predefined_constraints(field)
          return nil unless field.options

          extract_extension(
            field.options,
            EXTENSION_FIELD_NUMBER,
            Buf::Validate::PredefinedRules
          )
        end

        private

        # Extracts an extension from serialized protobuf options.
        #
        # @param options [Google::Protobuf::MessageExts] The options message
        # @param field_number [Integer] The extension field number to look for
        # @param message_class [Class] The class to decode the extension data into
        # @return [Google::Protobuf::MessageExts, nil] The decoded extension or nil
        def extract_extension(options, field_number, message_class)
          require "buf/validate/validate_pb"

          serialized = options.to_proto
          return nil if serialized.nil? || serialized.empty?

          extension_data = find_extension_data(serialized, field_number)
          return nil if extension_data.nil?

          message_class.decode(extension_data)
        rescue Google::Protobuf::ParseError, LoadError, NameError
          nil
        end

        # Finds extension data in serialized protobuf bytes.
        #
        # @param bytes [String] The serialized protobuf data
        # @param target_field_number [Integer] The field number to find
        # @return [String, nil] The extension data or nil
        def find_extension_data(bytes, target_field_number)
          data = bytes.b
          pos = 0

          while pos < data.bytesize
            # Decode the tag (varint)
            tag, pos = decode_varint(data, pos)
            return nil if tag.nil?

            field_number = tag >> 3
            wire_type = tag & 0x7

            case wire_type
            when 0 # Varint
              _, pos = decode_varint(data, pos)
            when 1 # 64-bit
              pos += 8
            when 2 # Length-delimited
              length, pos = decode_varint(data, pos)
              return nil if length.nil? || pos + length > data.bytesize

              return data[pos, length] if field_number == target_field_number

              pos += length
            when 5 # 32-bit
              pos += 4
            else
              # Unknown wire type, can't continue
              return nil
            end

            return nil if pos.nil?
          end

          nil
        end

        # Decodes a varint from bytes.
        #
        # @param data [String] The byte string
        # @param pos [Integer] Starting position
        # @return [Array(Integer, Integer), Array(nil, nil)] The value and new position
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
            return [nil, nil] if shift > 63 # Overflow protection
          end
        end
      end
    end
  end
end
