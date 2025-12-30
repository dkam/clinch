require "test_helper"

module Api
  class ForwardAuthControllerTest < ActionDispatch::IntegrationTest
    setup do
      @user = users(:bob)
      @admin_user = users(:alice)
      @inactive_user = User.create!(email_address: "inactive@example.com", password: "password", status: :disabled)
      @group = groups(:admin_group)
      @rule = Application.create!(name: "Test App", slug: "test-app", app_type: "forward_auth", domain_pattern: "test.example.com", active: true)
      @inactive_rule = Application.create!(name: "Inactive App", slug: "inactive-app", app_type: "forward_auth", domain_pattern: "inactive.example.com", active: false)
    end

    # Authentication Tests
    test "should redirect to login when no session cookie" do
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 302
      assert_match %r{/signin}, response.location
      assert_equal "No session cookie", response.headers["x-auth-reason"]
    end

    test "should redirect when user is inactive" do
      sign_in_as(@inactive_user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 302
      assert_equal "User account is not active", response.headers["x-auth-reason"]
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

    test "should return 403 when no rule matches (fail-closed security)" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "unknown.example.com" }

      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should return 403 when rule exists but is inactive" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "inactive.example.com" }

      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should return 403 when rule exists but user not in allowed groups" do
      @rule.allowed_groups << @group
      sign_in_as(@user)  # User not in group

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 403
      assert_match %r{permission to access this domain}, response.headers["x-auth-reason"]
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
      wildcard_rule = Application.create!(name: "Wildcard App", slug: "wildcard-app", app_type: "forward_auth", domain_pattern: "*.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "other.com" }
      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should match exact domains correctly" do
      exact_rule = Application.create!(name: "Exact App", slug: "exact-app", app_type: "forward_auth", domain_pattern: "api.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
      assert_response 200

      get "/api/verify", headers: { "X-Forwarded-Host" => "app.api.example.com" }
      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Header Configuration Tests
    test "should return default headers when rule has no custom config" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_equal @user.email_address, response.headers["x-remote-user"]
      assert_equal @user.email_address, response.headers["x-remote-email"]
      assert response.headers["x-remote-name"].present?
      assert_equal (@user.admin? ? "true" : "false"), response.headers["x-remote-admin"]
    end

    test "should return custom headers when configured" do
      custom_rule = Application.create!(
        name: "Custom App",
        slug: "custom-app",
        app_type: "forward_auth",
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
      assert_equal @user.email_address, response.headers["x-webauth-user"]
      assert_equal @user.email_address, response.headers["x-webauth-email"]
      # Default headers should NOT be present
      assert_nil response.headers["x-remote-user"]
      assert_nil response.headers["x-remote-email"]
    end

    test "should return no headers when all headers disabled" do
      no_headers_rule = Application.create!(
        name: "No Headers App",
        slug: "no-headers-app",
        app_type: "forward_auth",
        domain_pattern: "noheaders.example.com",
        active: true,
        headers_config: { user: "", email: "", name: "", groups: "", admin: "" }
      )
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "noheaders.example.com" }

      assert_response 200
      # Check that auth-specific headers are not present (exclude Rails security headers)
      auth_headers = response.headers.select { |k, v| k.match?(/^X-Remote-/i) || k.match?(/^X-WEBAUTH/i) }
      assert_empty auth_headers, "Should not have any auth headers when all are disabled"
    end

    test "should include groups header when user has groups" do
      @user.groups << @group
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      groups_header = response.headers["x-remote-groups"]
      assert_includes groups_header, @group.name
      # Bob also has editor_group from fixtures
      assert_includes groups_header, "Editors"
    end

    test "should not include groups header when user has no groups" do
      @user.groups.clear  # Remove fixture groups
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_nil response.headers["x-remote-groups"]
    end

    test "should include admin header correctly" do
      sign_in_as(@admin_user)  # Assuming users(:two) is admin

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      assert_equal "true", response.headers["x-remote-admin"]
    end

    test "should include multiple groups when user has multiple groups" do
      group2 = groups(:two)
      @user.groups << @group
      @user.groups << group2
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      assert_response 200
      groups_header = response.headers["x-remote-groups"]
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

      # User is authenticated but no domain rule matches (default test host)
      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Security Tests
    test "should handle very long domain names" do
      long_domain = "a" * 250 + ".example.com"
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => long_domain }

      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should handle case insensitive domain matching" do
      sign_in_as(@user)

      get "/api/verify", headers: { "X-Forwarded-Host" => "TEST.Example.COM" }

      assert_response 200
    end

    # Open Redirect Security Tests - All tests verify SECURE behavior
    test "should reject malicious redirect URL through session after authentication (SECURE BEHAVIOR)" do
      # This test shows malicious URLs are filtered out through the auth flow
      evil_url = "https://evil-site.com/fake-login"

      # Step 1: Request with malicious redirect URL
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Uri" => "/admin"
      }, params: { rd: evil_url }

      assert_response 302
      assert_match %r{/signin}, response.location

      # Step 2: Check that malicious URL is filtered out and legitimate URL is stored
      stored_url = session[:return_to_after_authenticating]
      refute_match evil_url, stored_url, "Malicious URL should not be stored in session"
      assert_match "test.example.com", stored_url, "Should store legitimate URL from X-Forwarded-Host"

      # Step 3: Authenticate and check redirect
      post "/signin", params: {
        email_address: @user.email_address,
        password: "password",
        rd: evil_url  # Ensure the rd parameter is preserved in login
      }

      assert_response 302
      # Should NOT redirect to evil URL after successful authentication
      refute_match evil_url, response.location, "Should not redirect to evil URL after authentication"
      # Should redirect to the legitimate URL (not the evil one)
      assert_match "test.example.com", response.location, "Should redirect to legitimate domain"
    end

    test "should ONLY allow redirects to domains with matching ForwardAuthRules (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be allowed (domain has ForwardAuthRule)
      allowed_url = "https://test.example.com/dashboard"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: allowed_url }

      assert_response 302
      assert_match allowed_url, response.location
    end

    test "should REJECT redirects to domains without matching ForwardAuthRules (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be rejected (no ForwardAuthRule for evil-site.com)
      evil_url = "https://evil-site.com/steal-credentials"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: evil_url }

      assert_response 302
      # Should redirect to login page or default URL, NOT to evil_url
      refute_match evil_url, response.location
      assert_match %r{/signin}, response.location
    end

    test "should REJECT redirects to non-HTTPS URLs in production (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be rejected (HTTP not HTTPS)
      http_url = "http://test.example.com/dashboard"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: http_url }

      assert_response 302
      # Should redirect to login page or default URL, NOT to HTTP URL
      refute_match http_url, response.location
      assert_match %r{/signin}, response.location
    end

    test "should REJECT redirects to dangerous URL schemes (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      dangerous_schemes = [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "vbscript:msgbox('XSS')",
        "file:///etc/passwd"
      ]

      dangerous_schemes.each do |dangerous_url|
        get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
            params: { rd: dangerous_url }

        assert_response 302, "Should reject dangerous URL: #{dangerous_url}"
        # Should redirect to login page or default URL, NOT to dangerous URL
        refute_match dangerous_url, response.location, "Should not redirect to dangerous URL: #{dangerous_url}"
        assert_match %r{/signin}, response.location, "Should redirect to login for dangerous URL: #{dangerous_url}"
      end
    end

    # HTTP Method Tests
    test "should handle GET requests with appropriate response codes" do
      sign_in_as(@user)

      # Authenticated GET requests should return 200
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 200
    end

    # XHR/Fetch Request Tests
    test "should handle XHR requests appropriately" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Requested-With" => "XMLHttpRequest"
      }

      assert_response 302
      # XHR requests should still redirect in our implementation
      # Authelia returns 401 for XHR, but that may not be suitable for all reverse proxies
    end

    test "should handle requests with JSON Accept headers" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Accept" => "application/json"
      }

      assert_response 302
      # Our implementation still redirects, which is appropriate for reverse proxy scenarios
    end

    # Edge Case and Security Tests
    test "should handle missing X-Forwarded-Host header gracefully" do
      get "/api/verify"

      # Should handle missing headers gracefully
      assert_response 302
      assert_match %r{/signin}, response.location
    end

    test "should handle malformed X-Forwarded-Host header" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "invalid[host]with[special]chars"
      }

      # Should handle malformed host gracefully
      assert_response 302
    end

    test "should handle very long X-Forwarded-Host header" do
      long_host = "a" * 300 + ".example.com"

      get "/api/verify", headers: {
        "X-Forwarded-Host" => long_host
      }

      # Should handle long host names gracefully
      assert_response 302
    end

    test "should handle special characters in X-Forwarded-URI" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Uri" => "/path/with%20spaces/and-special-chars?param=value&other=123"
      }

      assert_response 200
    end

    test "should handle unicode in X-Forwarded-Host" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "测试.example.com"
      }

      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Protocol and Scheme Tests
    test "should handle X-Forwarded-Proto header" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Proto" => "https"
      }

      assert_response 200
    end

    test "should handle HTTP protocol in X-Forwarded-Proto" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Proto" => "http"
      }

      assert_response 200
      # Note: Our implementation doesn't enforce protocol matching
    end

    # Session and State Tests
    test "should maintain session across multiple requests" do
      sign_in_as(@user)

      # First request
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 200

      # Second request with same session
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 200

      # Should maintain user identity across requests
      assert_equal @user.email_address, response.headers["x-remote-user"]
    end

    test "should handle concurrent requests with same session" do
      sign_in_as(@user)

      # Simulate multiple concurrent requests
      threads = []
      results = []

      5.times do |i|
        threads << Thread.new do
          get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
          results << { status: response.status }
        end
      end

      threads.each(&:join)

      # All requests should be denied (no rules configured for these domains)
      results.each do |result|
        assert_equal 403, result[:status]
      end
    end

    # Header Injection and Security Tests
    test "should handle malicious header injection attempts" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com\r\nMalicious-Header: injected-value"
      }

      # Should handle header injection attempts
      assert_response 302
    end

    test "should handle null byte injection in headers" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com\0.evil.com"
      }

      # Should handle null bytes safely - domain doesn't match any rule
      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Performance and Load Tests
    test "should handle requests efficiently under load" do
      sign_in_as(@user)

      start_time = Time.current
      request_count = 10

      request_count.times do |i|
        get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
        assert_response 403  # No rules configured for these domains
      end

      total_time = Time.current - start_time
      average_time = total_time / request_count

      # Should be reasonably fast (adjust threshold as needed)
      assert average_time < 0.1, "Average request time too slow: #{average_time}s"
    end
  end
end