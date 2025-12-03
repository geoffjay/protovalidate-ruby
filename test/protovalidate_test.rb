# frozen_string_literal: true

require "test_helper"

class ProtovalidateTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil Protovalidate::VERSION
  end

  def test_version_format
    assert_match(/\A\d+\.\d+\.\d+/, Protovalidate::VERSION)
  end

  def test_module_responds_to_validate
    assert_respond_to Protovalidate, :validate
  end

  def test_module_responds_to_collect_violations
    assert_respond_to Protovalidate, :collect_violations
  end

  def test_validate_with_nil_returns_no_error
    # nil messages should not raise
    assert_nil Protovalidate.validate(nil)
  end

  def test_collect_violations_with_nil_returns_empty
    violations = Protovalidate.collect_violations(nil)
    assert_empty violations
  end
end

class ViolationTest < Minitest::Test
  def test_violation_creation
    violation = Protovalidate::Violation.new(
      constraint_id: "test.constraint",
      message: "Test message"
    )

    assert_equal "test.constraint", violation.constraint_id
    assert_equal "Test message", violation.message
    refute violation.for_key
  end

  def test_violation_to_s
    violation = Protovalidate::Violation.new(
      constraint_id: "test.constraint",
      message: "Test message"
    )

    assert_equal "Test message", violation.to_s
  end

  def test_violation_with_field_path
    field_path = Protovalidate::FieldPath.new([
                                                Protovalidate::FieldPathElement.new(
                                                  field_number: 1,
                                                  field_name: "email",
                                                  field_type: :string
                                                )
                                              ])

    violation = Protovalidate::Violation.new(
      field_path: field_path,
      constraint_id: "string.email",
      message: "value must be a valid email"
    )

    assert_equal "email: value must be a valid email", violation.to_s
  end
end

class FieldPathTest < Minitest::Test
  def test_simple_path
    path = Protovalidate::FieldPath.new([
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "user",
                                            field_type: :message
                                          )
                                        ])

    assert_equal "user", path.to_s
  end

  def test_nested_path
    path = Protovalidate::FieldPath.new([
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "user",
                                            field_type: :message
                                          ),
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 2,
                                            field_name: "email",
                                            field_type: :string
                                          )
                                        ])

    assert_equal "user.email", path.to_s
  end

  def test_path_with_array_index
    path = Protovalidate::FieldPath.new([
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "items",
                                            field_type: :message
                                          ),
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "items",
                                            field_type: :message,
                                            subscript: 0,
                                            subscript_type: :index
                                          )
                                        ])

    assert_equal "items[0]", path.to_s
  end

  def test_path_with_string_key
    path = Protovalidate::FieldPath.new([
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "map_field",
                                            field_type: :message
                                          ),
                                          Protovalidate::FieldPathElement.new(
                                            field_number: 1,
                                            field_name: "map_field",
                                            field_type: :message,
                                            subscript: "key",
                                            subscript_type: :string_key
                                          )
                                        ])

    assert_equal "map_field[\"key\"]", path.to_s
  end
end

class ValidatorTest < Minitest::Test
  def test_validator_creation
    validator = Protovalidate::Validator.new
    assert_instance_of Protovalidate::Validator, validator
  end

  def test_validator_with_fail_fast
    validator = Protovalidate::Validator.new(fail_fast: true)
    assert_instance_of Protovalidate::Validator, validator
  end
end

class ErrorTest < Minitest::Test
  def test_compilation_error
    error = Protovalidate::CompilationError.new("Test error")
    assert_instance_of Protovalidate::CompilationError, error
    assert_equal "Test error", error.message
  end

  def test_compilation_error_with_cause
    cause = StandardError.new("Root cause")
    error = Protovalidate::CompilationError.new("Test error", cause: cause)

    assert_equal cause, error.cause
  end

  def test_runtime_error
    error = Protovalidate::RuntimeError.new("Runtime failure")
    assert_instance_of Protovalidate::RuntimeError, error
    assert_equal "Runtime failure", error.message
  end
end
