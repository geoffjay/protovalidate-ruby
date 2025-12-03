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
      return Bool.new(false) if @value.empty?

      # Reject control characters
      return Bool.new(false) if @value.match?(/[\x00-\x1f\x7f]/)

      # Reject invalid characters in query/fragment (but not in IPv6 brackets)
      # Zone IDs in URIs use %25 encoding
      uri_without_ipv6 = @value.gsub(/\[[^\]]*\]/, "")
      return Bool.new(false) if uri_without_ipv6.match?(/[<>\\^`{|}]/)

      # Validate percent encoding syntax (% must be followed by two hex digits)
      return Bool.new(false) unless valid_percent_encoding?(@value)

      # Handle IPv6 zone IDs (RFC 6874) which Ruby's URI.parse doesn't support
      # Zone IDs are encoded as %25 followed by the zone ID
      uri_for_parse = @value.gsub(/(\[[^\]]*?)%25[^\]]*(\])/, '\1\2')

      begin
        uri = URI.parse(uri_for_parse)
        Bool.new(uri.scheme && !uri.scheme.empty?)
      rescue URI::InvalidURIError
        Bool.new(false)
      end
    end

    define_cel_method(:isUriRef) do
      return Bool.new(true) if @value.empty?

      # Reject control characters
      return Bool.new(false) if @value.match?(/[\x00-\x1f\x7f]/)

      # Reject invalid characters in query/fragment
      return Bool.new(false) if @value.match?(/[<>\\^`{|}]/)

      # Validate percent encoding
      return Bool.new(false) unless valid_percent_encoding?(@value)

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

      # Remove trailing dot if present
      hostname = @value.end_with?(".") ? @value[0...-1] : @value
      labels = hostname.split(".")

      return Bool.new(false) if labels.empty?

      # Validate each label (RFC 1123 allows labels to start with digits)
      labels.each do |label|
        return Bool.new(false) if label.empty? || label.length > 63
        return Bool.new(false) if label.start_with?("-") || label.end_with?("-")
        return Bool.new(false) unless label.match?(/\A[A-Za-z0-9-]+\z/)
      end

      # The last label (TLD) must not be all digits
      return Bool.new(false) if labels.last.match?(/\A\d+\z/)

      Bool.new(true)
    end

    define_cel_method(:isIp) do |*args|
      version = args.first&.value || 0

      return Bool.new(false) if @value.empty?

      # Only valid versions are 0 (any), 4 (IPv4), and 6 (IPv6)
      return Bool.new(false) unless [0, 4, 6].include?(version)

      # Reject CIDR notation (that's isIpPrefix)
      return Bool.new(false) if @value.include?("/")

      # Reject bracketed IPs (brackets are only for URIs)
      return Bool.new(false) if @value.start_with?("[") || @value.end_with?("]")

      # Handle IPv6 zone IDs - strip them for validation
      # Zone IDs can contain any non-null character according to RFC 4007
      ip_str = @value
      if @value.include?("%")
        parts = @value.split("%", 2)
        ip_str = parts[0]
        zone_id = parts[1]
        # Zone ID must not be empty and must not contain null character
        return Bool.new(false) if zone_id.nil? || zone_id.empty?
        return Bool.new(false) if zone_id.include?("\x00")
      end

      begin
        addr = IPAddr.new(ip_str)
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

      # Only valid versions are 0 (any), 4 (IPv4), and 6 (IPv6)
      return Bool.new(false) unless [0, 4, 6].include?(version)

      # Reject trailing/leading whitespace
      return Bool.new(false) if @value != @value.strip

      # Reject zone IDs in prefixes
      return Bool.new(false) if @value.include?("%")

      begin
        parts = @value.split("/")
        return Bool.new(false) unless parts.length == 2

        ip_part = parts[0]
        prefix_part = parts[1]

        # Prefix length must be a valid integer without leading zeros
        return Bool.new(false) unless prefix_part.match?(/\A(0|[1-9][0-9]*)\z/)

        addr = IPAddr.new(ip_part)
        prefix_len = prefix_part.to_i

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
          network = IPAddr.new("#{ip_part}/#{prefix_len}")
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
        bracket_end = @value.rindex("]")
        return Bool.new(false) unless bracket_end

        host = @value[1...bracket_end]
        rest = @value[(bracket_end + 1)..]

        # Handle zone ID in IPv6
        # Zone IDs can contain any non-null character according to RFC 4007
        ip_str = host
        if host.include?("%")
          parts = host.split("%", 2)
          ip_str = parts[0]
          zone_id = parts[1]
          return Bool.new(false) if zone_id.nil? || zone_id.empty?
          return Bool.new(false) if zone_id.include?("\x00")
        end

        # Only check brackets in the IP part (zone ID can contain brackets)
        return Bool.new(false) if ip_str.include?("[") || ip_str.include?("]")

        begin
          addr = IPAddr.new(ip_str)
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
        # Use -1 to preserve trailing empty strings (e.g., "host:" -> ["host", ""])
        parts = @value.split(":", -1)
        if parts.length == 1
          # If it looks like an IP (all numeric labels), validate as IP
          Bool.new(!port_required && valid_host?(parts[0]))
        elsif parts.length == 2
          Bool.new(valid_host?(parts[0]) && valid_port?(parts[1]))
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

    def valid_host?(str)
      # If it looks like an IPv4 (all numeric dot-separated), validate as IPv4
      # Otherwise validate as hostname
      if str.match?(/\A[\d.]+\z/)
        valid_ipv4?(str)
      else
        valid_hostname?(str)
      end
    end

    def valid_hostname?(str)
      return false if str.empty?
      return false if str.length > 253

      # Remove trailing dot if present
      hostname = str.end_with?(".") ? str[0...-1] : str
      labels = hostname.split(".")

      return false if labels.empty?

      # Validate each label (RFC 1123 allows labels to start with digits)
      labels.each do |label|
        return false if label.empty? || label.length > 63
        return false if label.start_with?("-") || label.end_with?("-")
        return false unless label.match?(/\A[A-Za-z0-9-]+\z/)
      end

      # The last label (TLD) must not be all digits
      return false if labels.last.match?(/\A\d+\z/)

      true
    end

    def valid_ipv4?(str)
      return false if str.empty?
      return false if str.include?("/") # Reject CIDR notation

      # Must be exactly 4 octets
      parts = str.split(".")
      return false unless parts.length == 4

      parts.all? do |part|
        return false unless part.match?(/\A(0|[1-9][0-9]*)\z/)

        num = part.to_i
        num >= 0 && num <= 255
      end
    end

    def valid_port?(port_str)
      return false if port_str.empty?
      # Port must be a valid integer without leading zeros (except "0" itself)
      return false unless port_str.match?(/\A(0|[1-9][0-9]*)\z/)

      port = port_str.to_i
      port.between?(0, 65_535)
    end

    def valid_percent_encoding?(str)
      # Check that all % signs are followed by exactly two hex digits
      i = 0
      while i < str.length
        if str[i] == "%"
          # Must have at least two more characters
          return false if i + 2 >= str.length
          # Next two characters must be hex
          return false unless str[i + 1].match?(/[0-9A-Fa-f]/) && str[i + 2].match?(/[0-9A-Fa-f]/)
          i += 3
        else
          i += 1
        end
      end
      true
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
