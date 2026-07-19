require "test_helper"

class OidcHelperTest < ActionView::TestCase
  test "scope_description returns a human-readable label for each supported scope" do
    user = User.new(email_address: "person@example.com")
    assert_equal "Verify your identity", scope_description("openid", user: user)
    assert_equal "Access your email address (person@example.com)", scope_description("email", user: user)
    assert_equal "Access your profile information", scope_description("profile", user: user)
    assert_equal "Access your group memberships", scope_description("groups", user: user)
    assert_equal "Stay signed in (refresh access)", scope_description("offline_access", user: user)
  end

  test "scope_description covers every SUPPORTED_SCOPE (so the consent screens can't silently drop one)" do
    user = User.new(email_address: "person@example.com")
    OidcController::SUPPORTED_SCOPES.each do |scope|
      assert_not_equal scope, scope_description(scope, user: user),
        "#{scope} has no description and would render as its raw name"
    end
  end

  test "scope_description falls back to the raw scope name for unknown scopes" do
    assert_equal "somethingelse", scope_description("somethingelse", user: User.new)
  end
end
