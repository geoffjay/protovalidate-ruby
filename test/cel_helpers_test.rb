# frozen_string_literal: true

require "test_helper"

class CelHelpersTest < Minitest::Test
  def setup
    @helpers = Protovalidate::Internal::CelHelpers
  end

  # Email validation tests
  def test_valid_email
    assert valid_email?("user@example.com")
    assert valid_email?("user.name@example.com")
    assert valid_email?("user+tag@example.com")
    assert valid_email?("user@subdomain.example.com")
  end

  def test_invalid_email
    refute valid_email?("")
    refute valid_email?("notanemail")
    refute valid_email?("@example.com")
    refute valid_email?("user@")
    refute valid_email?("user@.com")
  end

  # URI validation tests
  def test_valid_uri
    assert valid_uri?("https://example.com")
    assert valid_uri?("http://example.com/path")
    assert valid_uri?("ftp://files.example.com")
    assert valid_uri?("mailto:user@example.com")
  end

  def test_invalid_uri
    refute valid_uri?("")
    refute valid_uri?("example.com")
    refute valid_uri?("/relative/path")
  end

  # Hostname validation tests
  def test_valid_hostname
    assert valid_hostname?("example.com")
    assert valid_hostname?("sub.example.com")
    assert valid_hostname?("localhost")
    assert valid_hostname?("example-site.com")
  end

  def test_invalid_hostname
    refute valid_hostname?("")
    refute valid_hostname?("-invalid.com")
    refute valid_hostname?("invalid-.com")
    refute valid_hostname?("a" * 64 + ".com") # Label too long
  end

  # IP address validation tests
  def test_valid_ipv4
    assert valid_ip?("192.168.1.1")
    assert valid_ip?("10.0.0.1")
    assert valid_ip?("127.0.0.1")
    assert valid_ip?("255.255.255.255")
  end

  def test_valid_ipv6
    assert valid_ip?("::1")
    assert valid_ip?("2001:db8::1")
    assert valid_ip?("fe80::1")
  end

  def test_ipv4_only
    assert valid_ip?("192.168.1.1", 4)
    refute valid_ip?("::1", 4)
  end

  def test_ipv6_only
    assert valid_ip?("::1", 6)
    refute valid_ip?("192.168.1.1", 6)
  end

  def test_invalid_ip
    refute valid_ip?("")
    refute valid_ip?("not.an.ip")
    refute valid_ip?("256.256.256.256")
  end

  # IP prefix validation tests
  def test_valid_ip_prefix
    assert valid_ip_prefix?("192.168.1.0/24")
    assert valid_ip_prefix?("10.0.0.0/8")
    assert valid_ip_prefix?("2001:db8::/32")
  end

  def test_invalid_ip_prefix
    refute valid_ip_prefix?("")
    refute valid_ip_prefix?("192.168.1.1")
    refute valid_ip_prefix?("192.168.1.0/33")
  end

  # Host and port validation tests
  def test_valid_host_and_port
    assert valid_host_and_port?("example.com:80", true)
    assert valid_host_and_port?("192.168.1.1:8080", true)
    assert valid_host_and_port?("[::1]:443", true)
  end

  def test_host_without_required_port
    refute valid_host_and_port?("example.com", true)
    assert valid_host_and_port?("example.com", false)
  end

  def test_invalid_host_and_port
    refute valid_host_and_port?("", true)
    refute valid_host_and_port?("example.com:99999", true)
    refute valid_host_and_port?("example.com:-1", true)
  end

  private

  def valid_email?(str)
    @helpers.send(:valid_email?, str)
  end

  def valid_uri?(str)
    @helpers.send(:valid_uri?, str)
  end

  def valid_hostname?(str)
    @helpers.send(:valid_hostname?, str)
  end

  def valid_ip?(str, version = 0)
    @helpers.send(:valid_ip?, str, version)
  end

  def valid_ip_prefix?(str, version = 0, strict = false)
    @helpers.send(:valid_ip_prefix?, str, version, strict)
  end

  def valid_host_and_port?(str, port_required)
    @helpers.send(:valid_host_and_port?, str, port_required)
  end
end
