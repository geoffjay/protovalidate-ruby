# frozen_string_literal: true

require "test_helper"

$LOAD_PATH.unshift File.expand_path("../gen", __dir__)

require "google/protobuf"
require "google/protobuf/any_pb"
require "buf/validate/conformance/harness/harness_pb"
require "buf/validate/conformance/cases/strings_pb"

class ConformanceRunnerTest < Minitest::Test
  def setup
    @runner = create_runner
  end

  def test_runner_processes_empty_request
    request = Buf::Validate::Conformance::Harness::TestConformanceRequest.new
    response = process_request(request)

    assert_instance_of Buf::Validate::Conformance::Harness::TestConformanceResponse, response
    assert_equal 0, response.results.size
  end

  def test_runner_processes_valid_message
    # Create a test case with a valid string
    test_case = Buf::Validate::Conformance::Cases::StringNone.new(val: "hello")

    # Wrap in Any
    any = Google::Protobuf::Any.new
    any.pack(test_case)

    # Create request
    request = Buf::Validate::Conformance::Harness::TestConformanceRequest.new(
      cases: { "test_valid" => any }
    )

    response = process_request(request)

    assert_equal 1, response.results.size
    result = response.results["test_valid"]
    assert result.success, "Expected success but got: #{result.inspect}"
  end

  def test_unpack_any_message
    test_case = Buf::Validate::Conformance::Cases::StringNone.new(val: "test")

    any = Google::Protobuf::Any.new
    any.pack(test_case)

    unpacked = @runner.send(:unpack_any, any)

    assert_instance_of Buf::Validate::Conformance::Cases::StringNone, unpacked
    assert_equal "test", unpacked.val
  end

  def test_unpack_any_with_invalid_type
    any = Google::Protobuf::Any.new(
      type_url: "type.googleapis.com/nonexistent.Type",
      value: ""
    )

    unpacked = @runner.send(:unpack_any, any)
    assert_nil unpacked
  end

  private

  def create_runner
    require_relative "../conformance/runner"
    Protovalidate::Conformance::Runner.new
  end

  def process_request(request)
    @runner.send(:process_request, request)
  end
end
