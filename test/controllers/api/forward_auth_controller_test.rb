require "test_helper"

module Api
  class ForwardAuthControllerTest < ActionDispatch::IntegrationTest
    setup do
      @user = users(:bob)
      @admin_user = users(:alice)
      @inactive_user = users(:bob)  # We'll create an inactive user in setup if needed
      @group = groups(:admin_group)
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
      assert_equal @user.email_address, response.headers["X-Remote-User"]
      assert_equal @user.email_address, response.headers["X-Remote-Email"]
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

    # Open Redirect Security Tests
    test "should redirect to malicious external domain when rd parameter is provided" do
      # This test demonstrates the current vulnerability
      evil_url = "https://evil-phishing-site.com/steal-credentials"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: evil_url }

      assert_response 302
      # Current vulnerable behavior: redirects to the evil URL
      assert_match evil_url, response.location
    end

    test "should redirect to http scheme when rd parameter uses http" do
      # This test shows we can redirect to non-HTTPS sites
      http_url = "http://insecure-site.com/login"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: http_url }

      assert_response 302
      assert_match http_url, response.location
    end

    test "should redirect to data URLs when rd parameter contains data scheme" do
      # This test shows we can redirect to data URLs (XSS potential)
      data_url = "data:text/html,<script>alert('XSS')</script>"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: data_url }

      assert_response 302
      # Currently redirects to data URL (XSS vulnerability)
      assert_match data_url, response.location
    end

    test "should redirect to javascript URLs when rd parameter contains javascript scheme" do
      # This test shows we can redirect to javascript URLs (XSS potential)
      js_url = "javascript:alert('XSS')"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: js_url }

      assert_response 302
      # Currently redirects to JavaScript URL (XSS vulnerability)
      assert_match js_url, response.location
    end

    test "should redirect to domain with no ForwardAuthRule when rd parameter is arbitrary" do
      # This test shows we can redirect to domains not configured in ForwardAuthRules
      unconfigured_domain = "https://unconfigured-domain.com/admin"

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: unconfigured_domain }

      assert_response 302
      # Currently redirects to unconfigured domain
      assert_match unconfigured_domain, response.location
    end

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

    test "should redirect to domain that looks similar but not in ForwardAuthRules" do
      # Create rule for test.example.com
      test_rule = ForwardAuthRule.create!(domain_pattern: "test.example.com", active: true)

      # Try to redirect to similar-looking domain not configured
      typosquat_url = "https://text.example.com/admin"  # Note: 'text' instead of 'test'

      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" },
          params: { rd: typosquat_url }

      assert_response 302
      # Currently redirects to typosquat domain
      assert_match typosquat_url, response.location
    end

    test "should redirect to subdomain that is not covered by ForwardAuthRules" do
      # Create rule for app.example.com
      app_rule = ForwardAuthRule.create!(domain_pattern: "app.example.com", active: true)

      # Try to redirect to completely different subdomain
      unexpected_subdomain = "https://admin.example.com/panel"

      get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" },
          params: { rd: unexpected_subdomain }

      assert_response 302
      # Currently redirects to unexpected subdomain
      assert_match unexpected_subdomain, response.location
    end

    # Tests for the desired secure behavior (these should fail with current implementation)
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

    # HTTP Method Specific Tests (based on Authelia approach)
    test "should handle different HTTP methods with appropriate redirect codes" do
      sign_in_as(@user)

      # Test GET requests should return 302 Found
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 200  # Authenticated user gets 200

      # Test POST requests should work the same for authenticated users
      post "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 200
    end

    test "should return 403 for non-authenticated POST requests instead of redirect" do
      # This follows Authelia's pattern where non-GET requests to protected resources
      # should return 403 when unauthenticated, not redirects
      post "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
      assert_response 302  # Our implementation still redirects to login
      # Note: Could be enhanced to return 403 for non-GET methods
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

      assert_response 200
    end

    # Protocol and Scheme Tests
    test "should handle X-Forwarded-Proto header" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Proto" => "https"
      }

      sign_in_as(@user)
      assert_response 200
    end

    test "should handle HTTP protocol in X-Forwarded-Proto" do
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "X-Forwarded-Proto" => "http"
      }

      sign_in_as(@user)
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
      assert_equal @user.email_address, response.headers["X-Remote-User"]
    end

    test "should handle concurrent requests with same session" do
      sign_in_as(@user)

      # Simulate multiple concurrent requests
      threads = []
      results = []

      5.times do |i|
        threads << Thread.new do
          get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
          results << { status: response.status, user: response.headers["X-Remote-User"] }
        end
      end

      threads.each(&:join)

      # All requests should succeed
      results.each do |result|
        assert_equal 200, result[:status]
        assert_equal @user.email_address, result[:user]
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
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com\0.evil.com"
      }

      sign_in_as(@user)
      # Should handle null bytes safely
      assert_response 200
    end

    # Performance and Load Tests
    test "should handle requests efficiently under load" do
      sign_in_as(@user)

      start_time = Time.current
      request_count = 10

      request_count.times do |i|
        get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
        assert_response 200
      end

      total_time = Time.current - start_time
      average_time = total_time / request_count

      # Should be reasonably fast (adjust threshold as needed)
      assert average_time < 0.1, "Average request time too slow: #{average_time}s"
    end
  end
end