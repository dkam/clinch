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

  # Header Configuration Tests
  test "effective_headers should return default headers when no custom config" do
    @rule.save!

    expected = ForwardAuthRule::DEFAULT_HEADERS
    assert_equal expected, @rule.effective_headers
  end

  test "effective_headers should merge custom headers with defaults" do
    @rule.save!
    @rule.update!(headers_config: { user: "X-Forwarded-User", email: "X-Forwarded-Email" })

    expected = ForwardAuthRule::DEFAULT_HEADERS.merge(
      user: "X-Forwarded-User",
      email: "X-Forwarded-Email"
    )
    assert_equal expected, @rule.effective_headers
  end

  test "headers_for_user should generate correct headers for user with groups" do
    group = groups(:one)
    user = users(:one)
    user.groups << group
    @rule.save!

    headers = @rule.headers_for_user(user)

    assert_equal user.email_address, headers["X-Remote-User"]
    assert_equal user.email_address, headers["X-Remote-Email"]
    assert_equal user.email_address, headers["X-Remote-Name"]
    assert_equal group.name, headers["X-Remote-Groups"]
    assert_equal "true", headers["X-Remote-Admin"]
  end

  test "headers_for_user should generate correct headers for user without groups" do
    user = users(:one)
    @rule.save!

    headers = @rule.headers_for_user(user)

    assert_equal user.email_address, headers["X-Remote-User"]
    assert_equal user.email_address, headers["X-Remote-Email"]
    assert_equal user.email_address, headers["X-Remote-Name"]
    assert_nil headers["X-Remote-Groups"]  # No groups, no header
    assert_equal "true", headers["X-Remote-Admin"]
  end

  test "headers_for_user should work with custom headers" do
    user = users(:one)
    @rule.update!(headers_config: {
      user: "X-Forwarded-User",
      groups: "X-Custom-Groups"
    })

    headers = @rule.headers_for_user(user)

    assert_equal user.email_address, headers["X-Forwarded-User"]
    assert_nil headers["X-Remote-User"]  # Should be overridden
    assert_equal user.email_address, headers["X-Remote-Email"]  # Default preserved
    assert_nil headers["X-Custom-Groups"]  # User has no groups
  end

  test "headers_for_user should return empty hash when all headers disabled" do
    user = users(:one)
    @rule.update!(headers_config: {
      user: "",
      email: "",
      name: "",
      groups: "",
      admin: ""
    })

    headers = @rule.headers_for_user(user)
    assert_empty headers
  end

  test "headers_disabled? should correctly identify disabled headers" do
    @rule.save!
    assert_not @rule.headers_disabled?

    @rule.update!(headers_config: { user: "X-Custom-User" })
    assert_not @rule.headers_disabled?

    @rule.update!(headers_config: { user: "", email: "", name: "", groups: "", admin: "" })
    assert @rule.headers_disabled?
  end

  # Additional Domain Pattern Tests
  test "matches_domain? should handle complex patterns" do
    @rule.save!

    # Test multiple wildcards
    @rule.update!(domain_pattern: "*.*.example.com")
    assert @rule.matches_domain?("app.dev.example.com")
    assert @rule.matches_domain?("api.staging.example.com")
    assert_not @rule.matches_domain?("example.com")
    assert_not @rule.matches_domain?("app.example.org")

    # Test exact domain with dots
    @rule.update!(domain_pattern: "api.v2.example.com")
    assert @rule.matches_domain?("api.v2.example.com")
    assert_not @rule.matches_domain?("api.v3.example.com")
    assert_not @rule.matches_domain?("v2.api.example.com")
  end

  test "matches_domain? should handle case insensitivity" do
    @rule.update!(domain_pattern: "*.EXAMPLE.COM")
    @rule.save!

    assert @rule.matches_domain?("app.example.com")
    assert @rule.matches_domain?("APP.EXAMPLE.COM")
    assert @rule.matches_domain?("App.Example.Com")
  end

  test "matches_domain? should handle empty and nil domains" do
    @rule.save!

    assert_not @rule.matches_domain?("")
    assert_not @rule.matches_domain?(nil)
  end

  # Advanced Header Configuration Tests
  test "headers_for_user should handle partial header configuration" do
    user = users(:one)
    user.groups << groups(:one)
    @rule.update!(headers_config: {
      user: "X-Custom-User",
      email: "",  # Disabled
      groups: "X-Custom-Groups"
    })
    @rule.save!

    headers = @rule.headers_for_user(user)

    # Should include custom user header
    assert_equal "X-Custom-User", headers.keys.find { |k| k.include?("User") }
    assert_equal user.email_address, headers["X-Custom-User"]

    # Should include default email header (not overridden)
    assert_equal "X-Remote-Email", headers.keys.find { |k| k.include?("Email") }
    assert_equal user.email_address, headers["X-Remote-Email"]

    # Should include custom groups header
    assert_equal "X-Custom-Groups", headers.keys.find { |k| k.include?("Groups") }
    assert_equal groups(:one).name, headers["X-Custom-Groups"]

    # Should include default name header (not overridden)
    assert_equal "X-Remote-Name", headers.keys.find { |k| k.include?("Name") }
  end

  test "headers_for_user should handle user without groups when groups header configured" do
    user = users(:one)
    user.groups.clear  # No groups
    @rule.update!(headers_config: { groups: "X-Custom-Groups" })
    @rule.save!

    headers = @rule.headers_for_user(user)

    # Should not include groups header for user with no groups
    assert_nil headers["X-Custom-Groups"]
    assert_nil headers["X-Remote-Groups"]
  end

  test "headers_for_user should handle non-admin user correctly" do
    user = users(:one)
    # Ensure user is not admin
    user.update!(admin: false)
    @rule.save!

    headers = @rule.headers_for_user(user)

    assert_equal "false", headers["X-Remote-Admin"]
  end

  test "headers_for_user should work with nil headers_config" do
    user = users(:one)
    @rule.update!(headers_config: nil)
    @rule.save!

    headers = @rule.headers_for_user(user)

    # Should use default headers
    assert_equal "X-Remote-User", headers.keys.find { |k| k.include?("User") }
    assert_equal user.email_address, headers["X-Remote-User"]
  end

  test "effective_headers should handle symbol keys in headers_config" do
    @rule.update!(headers_config: { user: "X-Symbol-User", email: "X-Symbol-Email" })
    @rule.save!

    effective = @rule.effective_headers

    assert_equal "X-Symbol-User", effective[:user]
    assert_equal "X-Symbol-Email", effective[:email]
    assert_equal "X-Remote-Name", effective[:name]  # Default
  end

  test "effective_headers should handle string keys in headers_config" do
    @rule.update!(headers_config: { "user" => "X-String-User", "email" => "X-String-Email" })
    @rule.save!

    effective = @rule.effective_headers

    assert_equal "X-String-User", effective[:user]
    assert_equal "X-String-Email", effective[:email]
    assert_equal "X-Remote-Name", effective[:name]  # Default
  end

  # Policy and Access Control Tests
  test "policy_for_user should handle user with TOTP enabled" do
    user = users(:one)
    user.update!(totp_secret: "test_secret")
    @rule.allowed_groups << groups(:one)
    user.groups << groups(:one)
    @rule.save!

    policy = @rule.policy_for_user(user)
    assert_equal "two_factor", policy
  end

  test "policy_for_user should handle user without TOTP" do
    user = users(:one)
    user.update!(totp_secret: nil)
    @rule.allowed_groups << groups(:one)
    user.groups << groups(:one)
    @rule.save!

    policy = @rule.policy_for_user(user)
    assert_equal "one_factor", policy
  end

  test "policy_for_user should handle user with multiple groups" do
    user = users(:one)
    group1 = groups(:one)
    group2 = groups(:two)
    @rule.allowed_groups << group1
    @rule.allowed_groups << group2
    user.groups << group1
    @rule.save!

    policy = @rule.policy_for_user(user)
    assert_equal "one_factor", policy
  end

  test "user_allowed? should handle user with multiple groups, one allowed" do
    user = users(:one)
    allowed_group = groups(:one)
    other_group = groups(:two)
    @rule.allowed_groups << allowed_group
    user.groups << allowed_group
    user.groups << other_group
    @rule.save!

    assert @rule.user_allowed?(user)
  end

  test "user_allowed? should handle user with multiple groups, none allowed" do
    user = users(:one)
    group1 = groups(:one)
    group2 = groups(:two)
    # Don't add any groups to allowed_groups
    user.groups << group1
    user.groups << group2
    @rule.save!

    assert_not @rule.user_allowed?(user)
  end
end
