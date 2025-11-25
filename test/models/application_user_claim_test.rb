require "test_helper"

class ApplicationUserClaimTest < ActiveSupport::TestCase
  def setup
    @user = users(:bob)
    @application = applications(:another_app)
  end

  test "should create valid application user claim" do
    claim = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: { "role": "admin" }
    )
    assert claim.valid?
    assert claim.save
  end

  test "should enforce uniqueness of user per application" do
    ApplicationUserClaim.create!(
      user: @user,
      application: @application,
      custom_claims: { "role": "admin" }
    )

    duplicate = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: { "role": "user" }
    )

    assert_not duplicate.valid?
    assert_includes duplicate.errors[:user_id], "has already been taken"
  end

  test "parsed_custom_claims returns hash" do
    claim = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: { "role": "admin", "level": 5 }
    )

    parsed = claim.parsed_custom_claims
    assert_equal "admin", parsed["role"]
    assert_equal 5, parsed["level"]
  end

  test "parsed_custom_claims returns empty hash when nil" do
    claim = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: nil
    )

    assert_equal({}, claim.parsed_custom_claims)
  end

  test "should not allow reserved OIDC claim names" do
    claim = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: { "groups": ["admin"], "role": "user" }
    )

    assert_not claim.valid?
    assert_includes claim.errors[:custom_claims], "cannot override reserved OIDC claims: groups"
  end

  test "should allow non-reserved claim names" do
    claim = ApplicationUserClaim.new(
      user: @user,
      application: @application,
      custom_claims: { "kavita_groups": ["admin"], "role": "user" }
    )

    assert claim.valid?
  end
end
