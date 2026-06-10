require "test_helper"

module Api
  class ForwardAuthControllerTest < ActionDispatch::IntegrationTest
    setup do
      @user = users(:bob)
      @admin_user = users(:alice)
      @inactive_user = User.create!(email_address: "inactive@example.com", password: "password", status: :disabled)
      @group = groups(:admin_group)
      @rule = grant_everyone_access(Application.create!(name: "Test App", slug: "test-app", app_type: "forward_auth", domain_pattern: "test.example.com", active: true))
      @inactive_rule = grant_everyone_access(Application.create!(name: "Inactive App", slug: "inactive-app", app_type: "forward_auth", domain_pattern: "inactive.example.com", active: false))
    end

    # Authentication Tests
    test "should redirect to login when no session cookie" do
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 302
      assert_match %r{/signin}, response.location
      assert_equal "No session cookie", response.headers["x-auth-reason"]
    end

    test "should redirect when user is inactive" do
      sign_in_as(@inactive_user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 302
      assert_equal "User account is not active", response.headers["x-auth-reason"]
    end

    test "should return 200 when user is authenticated" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
    end

    # Rule Matching Tests
    test "should return 200 when matching rule exists" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
    end

    test "should return 403 when no rule matches (fail-closed security)" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "unknown.example.com"}

      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should return 403 when rule exists but is inactive" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "inactive.example.com"}

      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should return 403 when rule exists but user not in allowed groups" do
      @rule.allowed_groups = [@group]
      sign_in_as(@user)  # User not in group

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 403
      assert_match %r{permission to access this domain}, response.headers["x-auth-reason"]
    end

    test "should return 200 when user is in allowed groups" do
      @rule.allowed_groups = [@group]
      @user.groups << @group
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
    end

    # Domain Pattern Tests
    test "should match wildcard domains correctly" do
      grant_everyone_access Application.create!(name: "Wildcard App", slug: "wildcard-app", app_type: "forward_auth", domain_pattern: "*.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "app.example.com"}
      assert_response 200

      get "/api/verify", headers: {"X-Forwarded-Host" => "api.example.com"}
      assert_response 200

      get "/api/verify", headers: {"X-Forwarded-Host" => "other.com"}
      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should match exact domains correctly" do
      grant_everyone_access Application.create!(name: "Exact App", slug: "exact-app", app_type: "forward_auth", domain_pattern: "api.example.com", active: true)
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "api.example.com"}
      assert_response 200

      get "/api/verify", headers: {"X-Forwarded-Host" => "app.api.example.com"}
      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Header Configuration Tests
    test "should return default headers when rule has no custom config" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
      assert_equal @user.email_address, response.headers["x-remote-user"]
      assert_equal @user.email_address, response.headers["x-remote-email"]
      assert response.headers["x-remote-name"].present?
      assert_equal (@user.admin? ? "true" : "false"), response.headers["x-remote-admin"]
    end

    test "should return custom headers when configured" do
      grant_everyone_access Application.create!(
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

      get "/api/verify", headers: {"X-Forwarded-Host" => "custom.example.com"}

      assert_response 200
      assert_equal @user.email_address, response.headers["x-webauth-user"]
      assert_equal @user.email_address, response.headers["x-webauth-email"]
      # Default headers should NOT be present
      assert_nil response.headers["x-remote-user"]
      assert_nil response.headers["x-remote-email"]
    end

    test "should return no headers when all headers disabled" do
      grant_everyone_access Application.create!(
        name: "No Headers App",
        slug: "no-headers-app",
        app_type: "forward_auth",
        domain_pattern: "noheaders.example.com",
        active: true,
        headers_config: {user: "", email: "", name: "", groups: "", admin: ""}
      )
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "noheaders.example.com"}

      assert_response 200
      # Check that auth-specific headers are not present (exclude Rails security headers)
      auth_headers = response.headers.select { |k, v| k.match?(/^X-Remote-/i) || k.match?(/^X-WEBAUTH/i) }
      assert_empty auth_headers, "Should not have any auth headers when all are disabled"
    end

    test "should include groups header when user has groups" do
      @user.groups << @group
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
      groups_header = response.headers["x-remote-groups"]
      assert_includes groups_header, @group.name
      # Bob also has editor_group from fixtures
      assert_includes groups_header, "Editors"
    end

    test "should not include groups header when user has no groups beyond the granting one and groups header empty" do
      # Under default-deny the user must be in at least one group to access the app.
      # This rewritten test verifies that when an app's headers_config disables the
      # groups header, no x-remote-groups is sent regardless of memberships.
      app = grant_everyone_access Application.create!(
        name: "Headers Hidden", slug: "headers-hidden", app_type: "forward_auth",
        domain_pattern: "hidden.example.com",
        active: true,
        headers_config: {groups: ""}
      )
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "hidden.example.com"}

      assert_response 200
      assert_nil response.headers["x-remote-groups"]
    end

    test "should include admin header correctly" do
      sign_in_as(@admin_user)  # Assuming users(:two) is admin

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
      assert_equal "true", response.headers["x-remote-admin"]
    end

    test "should include multiple groups when user has multiple groups" do
      group2 = groups(:two)
      @user.groups << @group
      @user.groups << group2
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 200
      groups_header = response.headers["x-remote-groups"]
      assert_includes groups_header, @group.name
      assert_includes groups_header, group2.name
    end

    # Header Fallback Tests
    test "should fall back to Host header when X-Forwarded-Host is missing" do
      sign_in_as(@user)

      get "/api/verify", headers: {"Host" => "test.example.com"}

      assert_response 200
    end

    test "should handle requests without any host headers" do
      sign_in_as(@user)

      get "/api/verify"

      # User is authenticated but no domain rule matches (default test host)
      assert_response 403
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    # Fail closed when no host can be determined: emitting identity headers without
    # an application would bypass all per-domain group access control.
    test "should fail closed and emit no identity headers when host is absent" do
      sign_in_as(@user)

      # Blank both host sources so forwarded_host is not present.
      get "/api/verify", headers: {"X-Forwarded-Host" => "", "Host" => ""}

      assert_response 403
      assert_equal "No host header present", response.headers["x-auth-reason"]
      assert_nil response.headers["X-Remote-User"]
      assert_nil response.headers["X-Remote-Groups"]
    end

    # Security Tests
    test "should handle very long domain names" do
      long_domain = "a" * 250 + ".example.com"
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => long_domain}

      assert_response 403  # No rule configured - fail-closed
      assert_equal "No authentication rule configured for this domain", response.headers["x-auth-reason"]
    end

    test "should handle case insensitive domain matching" do
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "TEST.Example.COM"}

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
      }, params: {rd: evil_url}

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

      assert_response 303
      # Should NOT redirect to evil URL after successful authentication
      refute_match evil_url, response.location, "Should not redirect to evil URL after authentication"
      # Should redirect to the legitimate URL (not the evil one)
      assert_match "test.example.com", response.location, "Should redirect to legitimate domain"
    end

    test "should ONLY allow redirects to domains with matching ForwardAuthRules (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be allowed (domain has ForwardAuthRule)
      allowed_url = "https://test.example.com/dashboard"

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"},
        params: {rd: allowed_url}

      assert_response 302
      assert_match allowed_url, response.location
    end

    test "should REJECT redirects to domains without matching ForwardAuthRules (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be rejected (no ForwardAuthRule for evil-site.com)
      evil_url = "https://evil-site.com/steal-credentials"

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"},
        params: {rd: evil_url}

      assert_response 302
      # Should redirect to login page or default URL, NOT to evil_url
      refute_match evil_url, response.location
      assert_match %r{/signin}, response.location
    end

    test "should REJECT redirects to non-HTTPS URLs in production (SECURE BEHAVIOR)" do
      # Use existing rule for test.example.com created in setup

      # This should be rejected (HTTP not HTTPS)
      http_url = "http://test.example.com/dashboard"

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"},
        params: {rd: http_url}

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
        get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"},
          params: {rd: dangerous_url}

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
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
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
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200

      # Second request with same session
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
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
          get "/api/verify", headers: {"X-Forwarded-Host" => "app#{i}.example.com"}
          results << {status: response.status}
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

    # Rate Limiting Tests
    test "should return 429 when rate limit exceeded" do
      cache = Rails.application.config.forward_auth_cache
      cache.write("fa_fail:127.0.0.1", 50, expires_in: 1.minute)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 429
      assert_equal "60", response.headers["Retry-After"]
    end

    test "should allow requests below rate limit" do
      cache = Rails.application.config.forward_auth_cache
      cache.write("fa_fail:127.0.0.1", 49, expires_in: 1.minute)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      assert_response 302 # unauthorized redirect, but not rate limited
    end

    test "should track failed attempts and eventually rate limit" do
      cache = Rails.application.config.forward_auth_cache

      # Make 50 failed requests (no session = unauthorized)
      50.times do
        get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      end

      # The 51st should be rate limited
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 429
    end

    test "should not track successful requests as failures" do
      cache = Rails.application.config.forward_auth_cache
      sign_in_as(@user)

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200

      count = cache.read("fa_fail:127.0.0.1")
      assert_nil count, "Successful requests should not increment failure counter"
    end

    # Caching Tests
    test "should debounce last_activity_at updates" do
      sign_in_as(@user)
      session = Session.last

      # First request should update last_activity_at
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200
      first_activity = session.reload.last_activity_at

      # Second request within 1 minute should NOT update
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200
      assert_equal first_activity, session.reload.last_activity_at
    end

    test "should bust app cache when forward auth application is saved" do
      cache = Rails.application.config.forward_auth_cache
      sign_in_as(@user)

      # Prime the cache
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200
      assert cache.read("fa_apps"), "Cache should be populated after request"

      # Update the application
      @rule.update!(name: "Updated App")

      assert_nil cache.read("fa_apps"), "Cache should be busted after application update"
    end

    test "should bust app cache when application group membership changes" do
      cache = Rails.application.config.forward_auth_cache
      sign_in_as(@user)

      # Prime the cache
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200
      assert cache.read("fa_apps"), "Cache should be populated after request"

      # Add a group to the application
      @rule.allowed_groups << @group

      assert_nil cache.read("fa_apps"), "Cache should be busted after adding group to application"

      # Prime cache again
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}

      # Remove the group
      @rule.application_groups.destroy_all

      assert_nil cache.read("fa_apps"), "Cache should be busted after removing group from application"
    end

    test "should persist first failure in rate limit cache" do
      cache = Rails.application.config.forward_auth_cache

      assert_nil cache.read("fa_fail:127.0.0.1"), "Counter should not exist before any failures"

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 302

      count = cache.read("fa_fail:127.0.0.1")
      assert_equal 1, count, "First failure should write counter with value 1"
    end

    test "should count bearer token failures toward rate limit" do
      cache = Rails.application.config.forward_auth_cache

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Authorization" => "Bearer invalid_token"
      }
      assert_response 401

      count = cache.read("fa_fail:127.0.0.1")
      assert_equal 1, count, "Bearer token failure should increment rate limit counter"
    end

    test "should rate limit bearer token requests after too many failures" do
      cache = Rails.application.config.forward_auth_cache
      cache.write("fa_fail:127.0.0.1", 50, expires_in: 1.minute)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "test.example.com",
        "Authorization" => "Bearer invalid_token"
      }

      assert_response 429
    end

    test "should reject rd parameter for deactivated application" do
      # Prime cache by triggering a lookup
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 302

      # Deactivate the app (this busts the cache via after_commit)
      @rule.update!(active: false)

      # Unauthenticated request with rd pointing to the now-inactive domain
      get "/api/verify", headers: {"X-Forwarded-Host" => "other.example.com"},
        params: {rd: "https://test.example.com/dashboard"}

      assert_response 302
      # The rd URL should be rejected since the app is inactive
      refute_match "test.example.com/dashboard", response.location
    end

    test "should update last_activity_at after debounce window expires" do
      sign_in_as(@user)
      session = Session.last

      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200
      first_activity = session.reload.last_activity_at

      # Travel past the 1-minute debounce window
      travel 61.seconds do
        get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
        assert_response 200
        assert_not_equal first_activity, session.reload.last_activity_at,
          "last_activity_at should update after debounce window expires"
      end
    end

    test "should not reset failure counter on successful request" do
      cache = Rails.application.config.forward_auth_cache
      # Simulate 30 prior failures
      cache.write("fa_fail:127.0.0.1", 30, expires_in: 1.minute)

      sign_in_as(@user)
      get "/api/verify", headers: {"X-Forwarded-Host" => "test.example.com"}
      assert_response 200

      count = cache.read("fa_fail:127.0.0.1")
      assert_equal 30, count, "Successful request should not reset or decrement failure counter"
    end

    # fa_token Host-Binding Tests (H-2)
    #
    # Rails.cache is a :null_store in test, so these cases swap in a
    # MemoryStore for the duration of each test and restore it after.
    class FaTokenHostBindingTest < ActionDispatch::IntegrationTest
      setup do
        @user = users(:bob)
        grant_everyone_access Application.create!(name: "Bound App", slug: "bound-app", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)

        @original_cache = Rails.cache
        Rails.cache = ActiveSupport::Cache::MemoryStore.new

        @session = Session.create!(user: @user, ip_address: "127.0.0.1", user_agent: "test")
        @token = "test-fa-token-123"
        Rails.cache.write(
          "forward_auth_token:#{@token}",
          {session_id: @session.id, host: "app.example.com"},
          expires_in: 60.seconds
        )
      end

      teardown do
        Rails.cache = @original_cache
      end

      test "matching X-Forwarded-Host allows redemption" do
        get "/api/verify", params: {fa_token: @token},
          headers: {"X-Forwarded-Host" => "app.example.com"}

        assert_response 200
        assert_nil Rails.cache.read("forward_auth_token:#{@token}"),
          "cache entry should be burned on successful redemption"
      end

      test "mismatched X-Forwarded-Host is rejected and cache entry survives" do
        get "/api/verify", params: {fa_token: @token},
          headers: {"X-Forwarded-Host" => "evil.example.com"}

        # Falls through to session-cookie auth; no cookie in this test -> 302 unauth redirect
        assert_response 302
        assert_equal "No session cookie", response.headers["x-auth-reason"]

        cached = Rails.cache.read("forward_auth_token:#{@token}")
        assert cached.is_a?(Hash), "cache entry must NOT be burned on host mismatch"
        assert_equal "app.example.com", cached[:host]
      end

      test "port in X-Forwarded-Host is ignored for host binding" do
        # Note: the subsequent Application domain-pattern match uses the raw
        # X-Forwarded-Host (with port) and would 403, but that's orthogonal to
        # the fa_token check. Successful binding is proven by the cache entry
        # being burned.
        get "/api/verify", params: {fa_token: @token},
          headers: {"X-Forwarded-Host" => "APP.example.com:8443"}

        assert_nil Rails.cache.read("forward_auth_token:#{@token}"),
          "port + case variation should still match the bound host and burn the token"
      end

      test "falls back to Host header when X-Forwarded-Host is missing" do
        get "/api/verify", params: {fa_token: @token},
          headers: {"Host" => "app.example.com"}

        assert_response 200
      end

      test "rejects when neither X-Forwarded-Host nor Host match" do
        get "/api/verify", params: {fa_token: @token},
          headers: {"Host" => "unknown.example.com"}

        assert_response 302
        cached = Rails.cache.read("forward_auth_token:#{@token}")
        assert cached.is_a?(Hash), "cache entry must survive mismatched Host"
      end
    end

    # fa_token Creation Tests (H-2)
    #
    # The URL-rewriting half of the H-2 fix: tokens are only created when the
    # return URL has a host. Path-only URLs must not produce an fa_token
    # (no cookie race exists for same-origin redirects, and there is no
    # host to bind against).
    class FaTokenCreationTest < ActionDispatch::IntegrationTest
      setup do
        @user = users(:bob)
        Application.create!(name: "Create App", slug: "create-app", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)

        @original_cache = Rails.cache
        Rails.cache = ActiveSupport::Cache::MemoryStore.new
      end

      teardown do
        Rails.cache = @original_cache
      end

      test "path-only return_to does not produce an fa_token or cache entry" do
        # Path-only rd (no host) — signin should not append fa_token.
        post "/signin",
          params: {email_address: @user.email_address, password: "password", rd: "/profile"}

        assert_response 303
        refute_match(/fa_token=/, response.location, "no fa_token for path-only return_to")
      end

      test "cross-origin return_to produces an fa_token bound to that host" do
        # First bounce through /api/verify to populate session[:return_to_after_authenticating]
        # with a full URL, then sign in.
        get "/api/verify", headers: {"X-Forwarded-Host" => "app.example.com"}
        assert_response 302

        post "/signin",
          params: {email_address: @user.email_address, password: "password"}
        assert_response 303

        # Extract the fa_token that was appended.
        assert_match(/fa_token=([^&]+)/, response.location)
        token = response.location[/fa_token=([^&]+)/, 1]

        cached = Rails.cache.read("forward_auth_token:#{token}")
        assert cached.is_a?(Hash), "cache entry should be a Hash, not legacy integer"
        assert_equal "app.example.com", cached[:host]
        assert cached[:session_id].present?
      end
    end

    # Performance and Load Tests
    test "should handle requests efficiently under load" do
      sign_in_as(@user)

      start_time = Time.current
      request_count = 10

      request_count.times do |i|
        get "/api/verify", headers: {"X-Forwarded-Host" => "app#{i}.example.com"}
        assert_response 403  # No rules configured for these domains
      end

      total_time = Time.current - start_time
      average_time = total_time / request_count

      # Should be reasonably fast (adjust threshold as needed)
      assert average_time < 0.1, "Average request time too slow: #{average_time}s"
    end
  end
end
