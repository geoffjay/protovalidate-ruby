# frozen_string_literal: true

module Protovalidate
  # Represents a single validation violation.
  class Violation
    # @return [FieldPath, nil] Path to the field that caused the violation
    attr_accessor :field_path

    # @return [Array<FieldPathElement>] Path elements to the rule that was violated
    attr_accessor :rule_path

    # @return [String] The constraint ID (e.g., "string.email")
    attr_reader :constraint_id

    # @return [String] Human-readable error message
    attr_reader :message

    # @return [Boolean] True if this violation is for a map key
    attr_reader :for_key

    # @return [Object, nil] The actual field value that failed validation
    attr_accessor :field_value

    # @return [Object, nil] The rule value used in validation
    attr_accessor :rule_value

    def initialize(
      field_path: nil,
      rule_path: [],
      constraint_id: "",
      message: "",
      for_key: false
    )
      @field_path = field_path
      @rule_path = rule_path
      @constraint_id = constraint_id
      @message = message
      @for_key = for_key
      @field_value = nil
      @rule_value = nil
    end

    # Converts this violation to a protobuf message.
    #
    # @return [Buf::Validate::Violation] The violation as a protobuf message
    def to_proto
      require_relative "../gen/buf/validate/validate_pb"

      Buf::Validate::Violation.new(
        field: field_path&.to_proto,
        rule: rule_path_to_proto,
        rule_id: constraint_id,
        message: message,
        for_key: for_key
      )
    end

    # Returns a string representation of the field path.
    #
    # @return [String] Dotted field path (e.g., "user.email" or "items[0].name")
    def field_path_string
      return "" unless field_path

      field_path.to_s
    end

    def to_s
      parts = []
      parts << field_path_string unless field_path_string.empty?
      parts << "[key]" if for_key
      parts << ": " unless parts.empty?
      parts << message
      parts.join
    end

    def inspect
      "#<#{self.class} #{self}>"
    end

    private

    def rule_path_to_proto
      require_relative "../gen/buf/validate/validate_pb"

      Buf::Validate::FieldPath.new(
        elements: rule_path.map(&:to_proto)
      )
    end
  end

  # Represents a path to a field in a protobuf message.
  class FieldPath
    # @return [Array<FieldPathElement>] The elements of the path
    attr_reader :elements

    def initialize(elements = [])
      @elements = elements
    end

    # Appends an element to the path.
    #
    # @param element [FieldPathElement] The element to append
    # @return [self]
    def <<(element)
      @elements << element
      self
    end

    # Returns the path as a dotted string.
    #
    # @return [String] The path string
    def to_s
      result = []
      elements.each do |elem|
        if elem.subscript
          result << elem.subscript_string
        else
          result << "." unless result.empty?
          result << elem.field_name
        end
      end
      result.join
    end

    # Converts this path to a protobuf message.
    #
    # @return [Buf::Validate::FieldPath] The path as a protobuf message
    def to_proto
      require_relative "../gen/buf/validate/validate_pb"

      Buf::Validate::FieldPath.new(
        elements: elements.map(&:to_proto)
      )
    end
  end

  # Represents a single element in a field path.
  class FieldPathElement
    # @return [Integer] The field number in the protobuf definition
    attr_reader :field_number

    # @return [String] The field name
    attr_reader :field_name

    # @return [Symbol] The field type (:int32, :string, :message, etc.)
    attr_reader :field_type

    # @return [Object, nil] The subscript value for map keys or repeated indices
    attr_reader :subscript

    # @return [Symbol, nil] The subscript type (:index, :bool_key, :int_key, :uint_key, :string_key)
    attr_reader :subscript_type

    # @return [Symbol, nil] The key type for map fields
    attr_reader :key_type

    # @return [Symbol, nil] The value type for map fields
    attr_reader :value_type

    def initialize(
      field_number:,
      field_name:,
      field_type:,
      subscript: nil,
      subscript_type: nil,
      key_type: nil,
      value_type: nil
    )
      @field_number = field_number
      @field_name = field_name
      @field_type = field_type
      @subscript = subscript
      @subscript_type = subscript_type
      @key_type = key_type
      @value_type = value_type
    end

    # Returns the subscript as a string for display.
    #
    # @return [String] The subscript string (e.g., "[0]" or '["key"]')
    def subscript_string
      return "" unless subscript

      case subscript_type
      when :index, :int_key, :uint_key
        "[#{subscript}]"
      when :bool_key
        "[#{subscript}]"
      when :string_key
        "[\"#{subscript}\"]"
      else
        "[#{subscript}]"
      end
    end

    # Converts this element to a protobuf message.
    #
    # @return [Buf::Validate::FieldPathElement] The element as a protobuf message
    def to_proto
      require_relative "../gen/buf/validate/validate_pb"

      elem = Buf::Validate::FieldPathElement.new(
        field_number: field_number,
        field_name: field_name,
        field_type: field_type_to_proto
      )

      # Set key_type and value_type for map fields
      if key_type
        elem.key_type = type_symbol_to_proto(key_type)
      end
      if value_type
        elem.value_type = type_symbol_to_proto(value_type)
      end

      case subscript_type
      when :index
        elem.index = subscript
      when :bool_key
        elem.bool_key = subscript
      when :int_key
        elem.int_key = subscript
      when :uint_key
        elem.uint_key = subscript
      when :string_key
        elem.string_key = subscript
      end

      elem
    end

    private

    TYPE_MAP = {
      double: :TYPE_DOUBLE,
      float: :TYPE_FLOAT,
      int64: :TYPE_INT64,
      uint64: :TYPE_UINT64,
      int32: :TYPE_INT32,
      fixed64: :TYPE_FIXED64,
      fixed32: :TYPE_FIXED32,
      bool: :TYPE_BOOL,
      string: :TYPE_STRING,
      group: :TYPE_GROUP,
      message: :TYPE_MESSAGE,
      bytes: :TYPE_BYTES,
      uint32: :TYPE_UINT32,
      enum: :TYPE_ENUM,
      sfixed32: :TYPE_SFIXED32,
      sfixed64: :TYPE_SFIXED64,
      sint32: :TYPE_SINT32,
      sint64: :TYPE_SINT64
    }.freeze

    def field_type_to_proto
      TYPE_MAP[field_type] || :TYPE_MESSAGE
    end

    def type_symbol_to_proto(type_sym)
      TYPE_MAP[type_sym] || :TYPE_MESSAGE
    end
  end
end
