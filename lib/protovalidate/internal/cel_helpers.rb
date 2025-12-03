# frozen_string_literal: true

require "cel"

module Protovalidate
  module Internal
    # Helper methods for CEL expression evaluation.
    module CelHelpers
      class << self
        # Returns declarations for custom CEL functions.
        #
        # @return [Hash] CEL function declarations
        def declarations
          {
            # String validation functions
            isEmail: Cel::Function(:string, return_type: :bool) { |s| valid_email?(s.to_s) },
            isUri: Cel::Function(:string, return_type: :bool) { |s| valid_uri?(s.to_s) },
            isUriRef: Cel::Function(:string, return_type: :bool) { |s| valid_uri_ref?(s.to_s) },
            isHostname: Cel::Function(:string, return_type: :bool) { |s| valid_hostname?(s.to_s) },
            isIp: Cel::Function(:string, return_type: :bool) { |s| valid_ip?(s.to_s) },
            "isIp.version": Cel::Function(:string, :int, return_type: :bool) { |s, v| valid_ip?(s.to_s, v.to_i) },
            isIpPrefix: Cel::Function(:string, return_type: :bool) { |s| valid_ip_prefix?(s.to_s) },
            isHostAndPort: Cel::Function(:string, :bool, return_type: :bool) do |s, req|
              valid_host_and_port?(s.to_s, req)
            end,

            # Number validation functions
            isNan: Cel::Function(:double, return_type: :bool) { |n| n.to_f.nan? },
            isInf: Cel::Function(:double, return_type: :bool) { |n| !n.to_f.infinite?.nil? },
            "isInf.sign": Cel::Function(:double, :int, return_type: :bool) do |n, sign|
              check_infinity?(n.to_f, sign.to_i)
            end,

            # Collection functions
            unique: Cel::Function(Cel::TYPES[:list, :any], return_type: :bool) { |list| list_unique?(list) }
          }
        end

        # Converts a protobuf message to a CEL activation (variable bindings).
        #
        # @param message [Google::Protobuf::MessageExts] The protobuf message
        # @return [Hash] CEL activation with 'this' bound to the message
        def message_to_activation(message)
          {
            this: message_to_cel(message),
            now: Time.now
          }
        end

        # Converts a field value to a CEL activation.
        #
        # @param value [Object] The field value
        # @param field [Google::Protobuf::FieldDescriptor] The field descriptor
        # @return [Hash] CEL activation with 'this' bound to the value
        def field_to_activation(value, field)
          {
            this: value_to_cel(value, field),
            now: Time.now
          }
        end

        private

        def message_to_cel(message)
          return nil if message.nil?

          # Convert message to a map-like structure for CEL
          result = {}
          message.class.descriptor.each do |field|
            value = message.send(field.name)
            result[field.name.to_s] = value_to_cel(value, field)
          end
          result
        end

        def value_to_cel(value, field)
          return nil if value.nil?

          case field&.type
          when :message
            if value.is_a?(Google::Protobuf::MessageExts)
              message_to_cel(value)
            else
              value
            end
          when :enum
            # Enums are represented as integers in CEL
            # Handle both symbol (named) and integer (numeric) enum values
            value.is_a?(Symbol) ? 0 : value.to_i
          else
            value
          end
        end

        def valid_email?(str)
          return false if str.empty?

          # HTML5 email validation pattern (simplified)
          pattern = %r{\A[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z}
          str.match?(pattern)
        end

        def valid_uri?(str)
          return false if str.empty?

          require "uri"
          uri = URI.parse(str)
          uri.scheme && !uri.scheme.empty?
        rescue URI::InvalidURIError
          false
        end

        def valid_uri_ref?(str)
          return true if str.empty?

          require "uri"
          URI.parse(str)
          true
        rescue URI::InvalidURIError
          false
        end

        def valid_hostname?(str)
          return false if str.empty?
          return false if str.length > 253

          # Hostname validation pattern
          pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?\z/
          str.match?(pattern)
        end

        def valid_ip?(str, version = 0)
          return false if str.empty?

          require "ipaddr"

          begin
            addr = IPAddr.new(str)
            case version
            when 4
              addr.ipv4?
            when 6
              addr.ipv6?
            else
              true
            end
          rescue IPAddr::InvalidAddressError
            false
          end
        end

        def valid_ip_prefix?(str, version = 0, strict = false)
          return false if str.empty?

          require "ipaddr"

          begin
            # IP prefix format: address/prefix_length
            parts = str.split("/")
            return false unless parts.length == 2

            addr = IPAddr.new(parts[0])
            prefix_len = parts[1].to_i

            case version
            when 4
              return false unless addr.ipv4?
              return false if prefix_len.negative? || prefix_len > 32
            when 6
              return false unless addr.ipv6?
              return false if prefix_len.negative? || prefix_len > 128
            else
              if addr.ipv4?
                return false if prefix_len.negative? || prefix_len > 32
              elsif prefix_len.negative? || prefix_len > 128
                return false
              end
            end

            if strict
              # Check if the address is the network address
              network = IPAddr.new("#{parts[0]}/#{prefix_len}")
              addr == network
            else
              true
            end
          rescue IPAddr::InvalidAddressError
            false
          end
        end

        def valid_host_and_port?(str, port_required)
          return false if str.empty?

          # Handle IPv6 addresses in brackets
          if str.start_with?("[")
            bracket_end = str.index("]")
            return false unless bracket_end

            host = str[1...bracket_end]
            rest = str[(bracket_end + 1)..]

            return false unless valid_ip?(host, 6)

            if rest.empty?
              !port_required
            elsif rest.start_with?(":")
              port = rest[1..]
              valid_port?(port)
            else
              false
            end
          else
            parts = str.split(":")
            if parts.length == 1
              !port_required && (valid_hostname?(parts[0]) || valid_ip?(parts[0]))
            elsif parts.length == 2
              (valid_hostname?(parts[0]) || valid_ip?(parts[0], 4)) && valid_port?(parts[1])
            else
              false
            end
          end
        end

        def valid_port?(port_str)
          return false if port_str.empty?
          return false unless port_str.match?(/\A\d+\z/)

          port = port_str.to_i
          port.between?(0, 65_535)
        end

        def check_infinity?(value, sign)
          inf = value.infinite?
          return false unless inf

          case sign
          when 0
            true # Any infinity
          when 1, true
            inf == 1 # Positive infinity
          when -1
            inf == -1 # Negative infinity
          else
            false
          end
        end

        def list_unique?(list)
          return true if list.nil? || list.empty?

          values = list.respond_to?(:to_a) ? list.to_a : list
          values.uniq.length == values.length
        end
      end
    end
  end
end
