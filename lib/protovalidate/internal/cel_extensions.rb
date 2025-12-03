# frozen_string_literal: true

require "cel"
require "uri"
require "ipaddr"

module Cel
  module Extensions
    module Protovalidate
      EXTENSION_NAME = :protovalidate

      module_function

      # Type checking support for protovalidate CEL functions
      def __check(funcall, checker:)
        var = funcall.var
        func = funcall.func
        args = funcall.args

        case func
        when :isEmail, :isUri, :isUriRef, :isHostname, :isIp, :isUuid
          if checker.call(var) == TYPES[:string]
            checker.check_arity(func, args, 0)
            return TYPES[:bool]
          end
        when :isIpPrefix
          if checker.call(var) == TYPES[:string]
            checker.check_arity(func, args, 0..2, :include?)
            return TYPES[:bool]
          end
        when :isHostAndPort
          if checker.call(var) == TYPES[:string]
            checker.check_arity(func, args, 1)
            arg = checker.call(args.first)
            return TYPES[:bool] if checker.find_match_all_types(%i[bool], arg)
          end
        when :isNan, :isInf
          var_type = checker.call(var)
          if var_type == TYPES[:double] || var_type == TYPES[:int]
            checker.check_arity(func, args, 0..1, :include?)
            return TYPES[:bool]
          end
        when :unique
          var_type = checker.call(var)
          if var_type.is_a?(Array) && var_type.first == :list
            checker.check_arity(func, args, 0)
            return TYPES[:bool]
          end
        end

        checker.unsupported_operation(funcall)
      end
    end
  end

  # Add protovalidate-specific methods to Cel::String
  class String
    define_cel_method(:isEmail) do
      email_pattern = %r{\A[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z}
      Bool.new(!@value.empty? && @value.match?(email_pattern))
    end

    define_cel_method(:isUri) do
      uri = URI.parse(@value)
      Bool.new(!@value.empty? && uri.scheme && !uri.scheme.empty?)
    rescue URI::InvalidURIError
      Bool.new(false)
    end

    define_cel_method(:isUriRef) do
      return Bool.new(true) if @value.empty?

      begin
        URI.parse(@value)
        Bool.new(true)
      rescue URI::InvalidURIError
        Bool.new(false)
      end
    end

    define_cel_method(:isHostname) do
      return Bool.new(false) if @value.empty?
      return Bool.new(false) if @value.length > 253

      hostname_pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?\z/
      Bool.new(@value.match?(hostname_pattern))
    end

    define_cel_method(:isIp) do |*args|
      version = args.first&.value || 0

      return Bool.new(false) if @value.empty?

      begin
        addr = IPAddr.new(@value)
        result = case version
                 when 4 then addr.ipv4?
                 when 6 then addr.ipv6?
                 else true
                 end
        Bool.new(result)
      rescue IPAddr::InvalidAddressError
        Bool.new(false)
      end
    end

    define_cel_method(:isIpPrefix) do |*args|
      version = args[0]&.value || 0
      strict = args[1]&.value || false

      return Bool.new(false) if @value.empty?

      begin
        parts = @value.split("/")
        return Bool.new(false) unless parts.length == 2

        addr = IPAddr.new(parts[0])
        prefix_len = parts[1].to_i

        case version
        when 4
          return Bool.new(false) unless addr.ipv4?
          return Bool.new(false) if prefix_len.negative? || prefix_len > 32
        when 6
          return Bool.new(false) unless addr.ipv6?
          return Bool.new(false) if prefix_len.negative? || prefix_len > 128
        else
          if addr.ipv4?
            return Bool.new(false) if prefix_len.negative? || prefix_len > 32
          elsif prefix_len.negative? || prefix_len > 128
            return Bool.new(false)
          end
        end

        if strict
          network = IPAddr.new("#{parts[0]}/#{prefix_len}")
          Bool.new(addr == network)
        else
          Bool.new(true)
        end
      rescue IPAddr::InvalidAddressError
        Bool.new(false)
      end
    end

    define_cel_method(:isHostAndPort) do |port_required|
      port_required = port_required.value if port_required.respond_to?(:value)

      return Bool.new(false) if @value.empty?

      # Handle IPv6 addresses in brackets
      if @value.start_with?("[")
        bracket_end = @value.index("]")
        return Bool.new(false) unless bracket_end

        host = @value[1...bracket_end]
        rest = @value[(bracket_end + 1)..]

        begin
          addr = IPAddr.new(host)
          return Bool.new(false) unless addr.ipv6?
        rescue IPAddr::InvalidAddressError
          return Bool.new(false)
        end

        if rest.empty?
          return Bool.new(!port_required)
        elsif rest.start_with?(":")
          port = rest[1..]
          return Bool.new(valid_port?(port))
        else
          return Bool.new(false)
        end
      else
        parts = @value.split(":")
        if parts.length == 1
          Bool.new(!port_required && (valid_hostname?(parts[0]) || valid_ip?(parts[0])))
        elsif parts.length == 2
          Bool.new((valid_hostname?(parts[0]) || valid_ip?(parts[0], 4)) && valid_port?(parts[1]))
        else
          Bool.new(false)
        end
      end
    end

    define_cel_method(:isUuid) do
      uuid_pattern = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/
      Bool.new(@value.match?(uuid_pattern))
    end

    private

    def valid_hostname?(str)
      return false if str.empty?
      return false if str.length > 253

      hostname_pattern = /\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?\z/
      str.match?(hostname_pattern)
    end

    def valid_ip?(str, version = 0)
      return false if str.empty?

      begin
        addr = IPAddr.new(str)
        case version
        when 4 then addr.ipv4?
        when 6 then addr.ipv6?
        else true
        end
      rescue IPAddr::InvalidAddressError
        false
      end
    end

    def valid_port?(port_str)
      return false if port_str.empty?
      return false unless port_str.match?(/\A\d+\z/)

      port = port_str.to_i
      port.between?(0, 65_535)
    end
  end

  # Add isNan and isInf to Number
  class Number
    define_cel_method(:isNan) do
      Bool.new(@type == :double && @value.nan?)
    end

    define_cel_method(:isInf) do |*args|
      sign = args.first&.value || 0

      return Bool.new(false) unless @type == :double

      inf = @value.infinite?
      return Bool.new(false) unless inf

      result = case sign
               when 0 then true
               when 1 then inf == 1
               when -1 then inf == -1
               else false
               end
      Bool.new(result)
    end
  end

  # Add unique to List
  class List
    define_cel_method(:unique) do
      values = @value.map { |v| v.respond_to?(:value) ? v.value : v }
      Bool.new(values.uniq.length == values.length)
    end
  end

  # Register the protovalidate extension if EXTENSIONS is available
  EXTENSIONS[:protovalidate] = Extensions::Protovalidate if defined?(EXTENSIONS) && EXTENSIONS.is_a?(Hash)
end
