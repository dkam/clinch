require "test_helper"

class ForwardAuthIntegrationTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:one)
    @admin_user = users(:two)
    @group = groups(:one)
    @group2 = groups(:two)

    # Create a forward_auth application for test.example.com
    @test_app = Application.create!(
      name: "Test App",
      slug: "test-app",
      app_type: "forward_auth",
      domain_pattern: "test.example.com",
      active: true
    )
  end

  # Basic Authentication Flow Tests
  test "complete authentication flow: unauthenticated to authenticated" do
    # Step 1: Unauthenticated request should redirect
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 302
    assert_match %r{/signin}, response.location
    assert_equal "No session cookie", response.headers["x-auth-reason"]

    # Step 2: Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302
    # Signin now redirects back with fa_token parameter
    assert_match(/\?fa_token=/, response.location)
    assert cookies[:session_id]

    # Step 3: Authenticated request should succeed
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
  end

  test "session expiration handling" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Manually expire the session (get the most recent session for this user)
    session = Session.where(user: @user).order(created_at: :desc).first
    assert session, "No session found for user"
    session.update!(expires_at: 1.hour.ago)

    # Request should fail and redirect to login
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 302
    assert_equal "Session expired", response.headers["x-auth-reason"]
  end

  # Domain and Rule Integration Tests
  test "different domain patterns with same session" do
    # Create test rules
    wildcard_rule = Application.create!(name: "Wildcard App", slug: "wildcard-app", app_type: "forward_auth", domain_pattern: "*.example.com", active: true)
    exact_rule = Application.create!(name: "Exact App", slug: "exact-app", app_type: "forward_auth", domain_pattern: "api.example.com", active: true)

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test wildcard domain
    get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]

    # Test exact domain
    get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]

    # Test non-matching domain (should use defaults)
    get "/api/verify", headers: { "X-Forwarded-Host" => "other.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
  end

  test "group-based access control integration" do
    # Create restricted rule
    restricted_rule = Application.create!(name: "Restricted App", slug: "restricted-app", app_type: "forward_auth", domain_pattern: "restricted.example.com", active: true)
    restricted_rule.allowed_groups << @group

    # Sign in user without group
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Should be denied access
    get "/api/verify", headers: { "X-Forwarded-Host" => "restricted.example.com" }
    assert_response 403
    assert_match %r{permission to access this domain}, response.headers["x-auth-reason"]

    # Add user to group
    @user.groups << @group

    # Should now be allowed
    get "/api/verify", headers: { "X-Forwarded-Host" => "restricted.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
  end

  # Header Configuration Integration Tests
  test "different header configurations with same user" do
    # Create applications with different configs
    default_rule = Application.create!(name: "Default App", slug: "default-app", app_type: "forward_auth", domain_pattern: "default.example.com", active: true)
    custom_rule = Application.create!(
      name: "Custom App", slug: "custom-app", app_type: "forward_auth",
      domain_pattern: "custom.example.com",
      active: true,
      headers_config: { user: "X-WEBAUTH-USER", groups: "X-WEBAUTH-ROLES" }
    )
    no_headers_rule = Application.create!(
      name: "No Headers App", slug: "no-headers-app", app_type: "forward_auth",
      domain_pattern: "noheaders.example.com",
      active: true,
      headers_config: { user: "", email: "", name: "", groups: "", admin: "" }
    )

    # Add user to groups
    @user.groups << @group
    @user.groups << @group2

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test default headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "default.example.com" }
    assert_response 200
    # Rails normalizes header keys to lowercase
    assert_equal @user.email_address, response.headers["x-remote-user"]
    assert response.headers.key?("x-remote-groups")
    assert_equal "Group Two,Group One", response.headers["x-remote-groups"]

    # Test custom headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "custom.example.com" }
    assert_response 200
    # Custom headers are also normalized to lowercase
    assert_equal @user.email_address, response.headers["x-webauth-user"]
    assert response.headers.key?("x-webauth-roles")
    assert_equal "Group Two,Group One", response.headers["x-webauth-roles"]

    # Test no headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "noheaders.example.com" }
    assert_response 200
    # Check that no auth-related headers are present (excluding security headers)
    auth_headers = response.headers.select { |k, v| k.match?(/^x-remote-|^x-webauth-|^x-admin-/i) }
    assert_empty auth_headers
  end

  # Redirect URL Integration Tests
  test "unauthenticated request redirects to signin with parameters" do
    # Test that unauthenticated requests redirect to signin with rd and rm parameters
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "grafana.example.com"
    }, params: {
      rd: "https://grafana.example.com/dashboard",
      rm: "GET"
    }

    assert_response 302
    location = response.location

    # Should redirect to signin with parameters (rd contains the original URL)
    assert_includes location, "/signin"
    assert_includes location, "rd="
    assert_includes location, "rm=GET"
    # The rd parameter should contain the original grafana.example.com URL
    assert_includes location, "grafana.example.com"
  end

  test "return URL functionality after authentication" do
    # Initial request should set return URL
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "app.example.com",
      "X-Forwarded-Uri" => "/admin"
    }, params: { rd: "https://app.example.com/admin" }

    assert_response 302
    location = response.location

    # Should contain the redirect URL parameter
    assert_includes location, "rd="
    assert_includes location, CGI.escape("https://app.example.com/admin")

    # Store session return URL
    return_to_after_authenticating = session[:return_to_after_authenticating]
    assert_equal "https://app.example.com/admin", return_to_after_authenticating
  end

  # Multiple User Scenarios Integration Tests
  test "multiple users with different access levels" do
    regular_user = users(:one)
    admin_user = users(:two)

    # Create restricted rule
    admin_rule = Application.create!(
      name: "Admin App", slug: "admin-app", app_type: "forward_auth",
      domain_pattern: "admin.example.com",
      active: true,
      headers_config: { user: "X-Admin-User", admin: "X-Admin-Flag" }
    )

    # Test regular user
    post "/signin", params: { email_address: regular_user.email_address, password: "password" }
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    assert_equal regular_user.email_address, response.headers["x-admin-user"]

    # Sign out
    delete "/session"

    # Test admin user
    post "/signin", params: { email_address: admin_user.email_address, password: "password" }
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    assert_equal admin_user.email_address, response.headers["x-admin-user"]
    assert_equal "true", response.headers["x-admin-flag"]
  end

  # Security Integration Tests
  test "session hijacking prevention" do
    # User A signs in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Verify User A can access protected resources
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
    user_a_session_id = Session.where(user: @user).last.id

    # Reset integration test session (but keep User A's session in database)
    reset!

    # User B signs in (creates a new session)
    post "/signin", params: { email_address: @admin_user.email_address, password: "password" }

    # Verify User B can access protected resources
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200
    assert_equal @admin_user.email_address, response.headers["x-remote-user"]
    user_b_session_id = Session.where(user: @admin_user).last.id

    # Verify both sessions still exist in the database
    assert Session.exists?(user_a_session_id), "User A's session should still exist"
    assert Session.exists?(user_b_session_id), "User B's session should still exist"
  end

end