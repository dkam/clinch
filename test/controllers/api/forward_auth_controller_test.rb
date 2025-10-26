require "test_helper"

module Api
  class ForwardAuthControllerTest < ActionDispatch::IntegrationTest
    setup do
      @user = users(:one)
      @admin_user = users(:two)
      @inactive_user = users(:three)
      @group = groups(:one)
      @rule = ForwardAuthRule.create!(domain_pattern: "test.example.com", active: true)
      @inactive_rule = ForwardAuthRule.create!(domain_pattern: "inactive.example.com", active: false)
    end

    # Authentication Tests
    test "should redirect to login when no session cookie" do
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 302
      assert_match %r{/signin}, response.location
      assert_equal "No session cookie", response.headers["X-Auth-Reason"]
    end

    test "should redirect when session cookie is invalid" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Cookie" => "_clinch_session_id=invalid_session_id"
      }

      assert_response 302
      assert_match %r{/signin}, response.location
      assert_equal "Invalid session", response.headers["X-Auth-Reason"]
    end

    test "should redirect when session is expired" do
      expired_session = @user.sessions.create!(created_at: 1.year.ago)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Cookie" => "_clinch_session_id=#{expired_session.id}"
      }

      assert_response 302
      assert_match %r{/signin}, response.location
      assert_equal "Session expired", response.headers["X-Auth-Reason"]
    end

    test "should redirect when user is inactive" do
      sign_in_as(@inactive_user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 302
      assert_equal "User account is not active", response.headers["X-Auth-Reason"]
    end

    test "should return 200 when user is authenticated" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
    end

    # Rule Matching Tests
    test "should return 200 when matching rule exists" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
    end

    test "should return 200 with default headers when no rule matches" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "unknown.example.com" }

      assert_response 200
      assert_equal "X-Remote-User", response.headers["X-Remote-User"]
      assert_equal @user.email_address, response.headers["X-Remote-User"]
    end

    test "should return 403 when rule exists but is inactive" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "inactive.example.com" }

      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["X-Auth-Reason"]
    end

    test "should return 403 when rule exists but user not in allowed groups" do
      @rule.allowed_groups << @group
      sign_in_as(@user)  # User not in group

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 403
      assert_match %r{permission to access this domain}, response.headers["X-Auth-Reason"]
    end

    test "should return 200 when user is in allowed groups" do
      @rule.allowed_groups << @group
      @user.groups << @group
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
    end

    # Domain Pattern Tests
    test "should match wildcard domains correctly" do
      wildcard_rule = ForwardAuthRule.create!(domain_pattern: "*.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "other.com" }
      assert_response 200  # Falls back to default behavior
    end

    test "should match exact domains correctly" do
      exact_rule = ForwardAuthRule.create!(domain_pattern: "api.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "app.api.example.com" }
      assert_response 200  # Falls back to default behavior
    end

    # Header Configuration Tests
    test "should return default headers when rule has no custom config" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_equal "X-Remote-User", response.headers.keys.find { |k| k.include?("User") }
      assert_equal "X-Remote-Email", response.headers.keys.find { |k| k.include?("Email") }
      assert_equal "X-Remote-Name", response.headers.keys.find { |k| k.include?("Name") }
      assert_equal @user.email_address, response.headers["X-Remote-User"]
    end

    test "should return custom headers when configured" do
      custom_rule = ForwardAuthRule.create!(
        domain_pattern: "custom.example.com",
        active: true,
        headers_config: {
          user: "X-WEBAUTH-USER",
          email: "X-WEBAUTH-EMAIL",
          groups: "X-WEBAUTH-ROLES"
        }
      )
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "custom.example.com" }

      assert_response 200
      assert_equal "X-WEBAUTH-USER", response.headers.keys.find { |k| k.include?("USER") }
      assert_equal "X-WEBAUTH-EMAIL", response.headers.keys.find { |k| k.include?("EMAIL") }
      assert_equal @user.email_address, response.headers["X-WEBAUTH-USER"]
    end

    test "should return no headers when all headers disabled" do
      no_headers_rule = ForwardAuthRule.create!(
        domain_pattern: "noheaders.example.com",
        active: true,
        headers_config: { user: "", email: "", name: "", groups: "", admin: "" }
      )
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "noheaders.example.com" }

      assert_response 200
      auth_headers = response.headers.select { |k, v| k.match?(/^(X-|Remote-)/i) }
      assert_empty auth_headers
    end

    test "should include groups header when user has groups" do
      @user.groups << @group
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_equal @group.name, response.headers["X-Remote-Groups"]
    end

    test "should not include groups header when user has no groups" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_nil response.headers["X-Remote-Groups"]
    end

    test "should include admin header correctly" do
      sign_in_as(@admin_user)  # Assuming users(:two) is admin

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_equal "true", response.headers["X-Remote-Admin"]
    end

    test "should include multiple groups when user has multiple groups" do
      group2 = groups(:two)
      @user.groups << @group
      @user.groups << group2
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      groups_header = response.headers["X-Remote-Groups"]
      assert_includes groups_header, @group.name
      assert_includes groups_header, group2.name
    end

    # Header Fallback Tests
    test "should fall back to Host header when X-Forwarded-Host is missing" do
      sign_in_as(@user)

      get "/api/verify", headers: { "Host" => "test.example.com" }

      assert_response 200
    end

    test "should handle requests without any host headers" do
      sign_in_as(@user)

      get "/api/verify"

      assert_response 200
      assert_equal "User #{@user.email_address} authenticated (no domain specified)",
                   request.env["action_dispatch.instance"].instance_variable_get(:@logged_messages)&.last
    end

    # Security Tests
    test "should handle malformed session IDs gracefully" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Cookie" => "_clinch_session_id=malformed_session_id_with_special_chars!@#$%"
      }

      assert_response 302
      assert_equal "Invalid session", response.headers["X-Auth-Reason"]
    end

    test "should handle very long domain names" do
      long_domain = "a" * 250 + ".example.com"
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => long_domain }

      assert_response 200  # Should fall back to default behavior
    end

    test "should handle case insensitive domain matching" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "TEST.Example.COM" }

      assert_response 200
    end
  end
end