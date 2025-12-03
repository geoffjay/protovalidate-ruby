# frozen_string_literal: true

module Protovalidate
  module Internal
    # Resolves validation constraints from protobuf descriptors.
    # Reads the buf.validate extensions to extract validation rules.
    module ConstraintResolver
      class << self
        # Resolves message-level validation constraints.
        #
        # @param descriptor [Google::Protobuf::Descriptor] The message descriptor
        # @return [Buf::Validate::MessageConstraints, nil] The message constraints or nil
        def resolve_message_constraints(descriptor)
          return nil unless descriptor.options

          # Try to get the message constraint extension
          begin
            require_relative "../../gen/buf/validate/validate_pb"

            # Access the extension field
            ext = descriptor.options[:".buf.validate.message"]
            return ext if ext
          rescue LoadError, NameError
            # Proto files not generated yet
            nil
          end

          nil
        end

        # Resolves field-level validation constraints.
        #
        # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
        # @return [Buf::Validate::FieldConstraints, nil] The field constraints or nil
        def resolve_field_constraints(field)
          return nil unless field.options

          begin
            require_relative "../../gen/buf/validate/validate_pb"

            # Access the extension field
            ext = field.options[:".buf.validate.field"]
            return ext if ext
          rescue LoadError, NameError
            # Proto files not generated yet
            nil
          end

          nil
        end

        # Resolves oneof-level validation constraints.
        #
        # @param oneof [Google::Protobuf::OneofDescriptor] The oneof descriptor
        # @return [Buf::Validate::OneofConstraints, nil] The oneof constraints or nil
        def resolve_oneof_constraints(oneof)
          return nil unless oneof.options

          begin
            require_relative "../../gen/buf/validate/validate_pb"

            # Access the extension field
            ext = oneof.options[:".buf.validate.oneof"]
            return ext if ext
          rescue LoadError, NameError
            # Proto files not generated yet
            nil
          end

          nil
        end

        # Resolves predefined validation rules.
        #
        # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
        # @return [Buf::Validate::PredefinedConstraints, nil] The predefined constraints or nil
        def resolve_predefined_constraints(field)
          return nil unless field.options

          begin
            require_relative "../../gen/buf/validate/validate_pb"

            # Access the extension field
            ext = field.options[:".buf.validate.predefined"]
            return ext if ext
          rescue LoadError, NameError
            # Proto files not generated yet
            nil
          end

          nil
        end
      end
    end
  end
end
