require "test_helper"

class ForwardAuthRuleTest < ActiveSupport::TestCase
  def setup
    @rule = ForwardAuthRule.new(
      domain_pattern: "*.example.com",
      active: true
    )
  end

  test "should be valid with valid attributes" do
    assert @rule.valid?
  end

  test "should require domain_pattern" do
    @rule.domain_pattern = ""
    assert_not @rule.valid?
    assert_includes @rule.errors[:domain_pattern], "can't be blank"
  end

  test "should require active to be boolean" do
    @rule.active = nil
    assert_not @rule.valid?
    assert_includes @rule.errors[:active], "is not included in the list"
  end

  test "should normalize domain_pattern to lowercase" do
    @rule.domain_pattern = "*.EXAMPLE.COM"
    @rule.save!
    assert_equal "*.example.com", @rule.reload.domain_pattern
  end

  test "should enforce unique domain_pattern" do
    @rule.save!
    duplicate = ForwardAuthRule.new(
      domain_pattern: "*.example.com",
      active: true
    )
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:domain_pattern], "has already been taken"
  end

  test "should match domain patterns correctly" do
    @rule.save!

    assert @rule.matches_domain?("app.example.com")
    assert @rule.matches_domain?("api.example.com")
    assert @rule.matches_domain?("sub.app.example.com")
    assert_not @rule.matches_domain?("example.org")
    assert_not @rule.matches_domain?("otherexample.com")
  end

  test "should handle exact domain matches" do
    @rule.domain_pattern = "api.example.com"
    @rule.save!

    assert @rule.matches_domain?("api.example.com")
    assert_not @rule.matches_domain?("app.example.com")
    assert_not @rule.matches_domain?("sub.api.example.com")
  end

  test "policy_for_user should return bypass when no groups assigned" do
    user = users(:one)
    @rule.save!

    assert_equal "bypass", @rule.policy_for_user(user)
  end

  test "policy_for_user should return deny for inactive rule" do
    user = users(:one)
    @rule.active = false
    @rule.save!

    assert_equal "deny", @rule.policy_for_user(user)
  end

  test "policy_for_user should return deny for inactive user" do
    user = users(:one)
    user.update!(active: false)
    @rule.save!

    assert_equal "deny", @rule.policy_for_user(user)
  end

  test "policy_for_user should return correct policy based on user groups and TOTP" do
    group = groups(:one)
    user_with_totp = users(:two)
    user_without_totp = users(:one)

    user_with_totp.totp_secret = "test_secret"
    user_with_totp.save!

    @rule.allowed_groups << group
    user_with_totp.groups << group
    user_without_totp.groups << group
    @rule.save!

    assert_equal "two_factor", @rule.policy_for_user(user_with_totp)
    assert_equal "one_factor", @rule.policy_for_user(user_without_totp)
  end

  test "user_allowed? should return true when no groups assigned" do
    user = users(:one)
    @rule.save!

    assert @rule.user_allowed?(user)
  end

  test "user_allowed? should return true when user in allowed groups" do
    group = groups(:one)
    user = users(:one)
    user.groups << group
    @rule.allowed_groups << group
    @rule.save!

    assert @rule.user_allowed?(user)
  end

  test "user_allowed? should return false when user not in allowed groups" do
    group = groups(:one)
    user = users(:one)
    @rule.allowed_groups << group
    @rule.save!

    assert_not @rule.user_allowed?(user)
  end
end
