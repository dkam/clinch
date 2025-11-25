require "test_helper"

class ForwardAuthIntegrationTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:one)
    @admin_user = users(:two)
    @group = groups(:one)
    @group2 = groups(:two)
  end

  # Basic Authentication Flow Tests
  test "complete authentication flow: unauthenticated to authenticated" do
    # Step 1: Unauthenticated request should redirect
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 302
    assert_match %r{/signin}, response.location
    assert_equal "No session cookie", response.headers["X-Auth-Reason"]

    # Step 2: Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_redirected_to "/"
    assert cookies[:session_id]

    # Step 3: Authenticated request should succeed
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]
  end

  test "session persistence across multiple requests" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    session_cookie = cookies[:session_id]
    assert session_cookie

    # Multiple requests should work with same session
    3.times do |i|
      get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
      assert_response 200
      assert_equal @user.email_address, response.headers["X-Remote-User"]
    end
  end

  test "session expiration handling" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Manually expire the session
    session = Session.find_by(id: cookies.signed[:session_id])
    session.update!(created_at: 1.year.ago)

    # Request should fail and redirect to login
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 302
    assert_equal "Session expired", response.headers["X-Auth-Reason"]
  end

  # Domain and Rule Integration Tests
  test "different domain patterns with same session" do
    # Create test rules
    wildcard_rule = Application.create!(domain_pattern: "*.example.com", active: true)
    exact_rule = Application.create!(domain_pattern: "api.example.com", active: true)

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test wildcard domain
    get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]

    # Test exact domain
    get "/api/verify", headers: { "X-Forwarded-Host" => "api.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]

    # Test non-matching domain (should use defaults)
    get "/api/verify", headers: { "X-Forwarded-Host" => "other.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]
  end

  test "group-based access control integration" do
    # Create restricted rule
    restricted_rule = Application.create!(domain_pattern: "restricted.example.com", active: true)
    restricted_rule.allowed_groups << @group

    # Sign in user without group
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Should be denied access
    get "/api/verify", headers: { "X-Forwarded-Host" => "restricted.example.com" }
    assert_response 403
    assert_match %r{permission to access this domain}, response.headers["X-Auth-Reason"]

    # Add user to group
    @user.groups << @group

    # Should now be allowed
    get "/api/verify", headers: { "X-Forwarded-Host" => "restricted.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]
  end

  # Header Configuration Integration Tests
  test "different header configurations with same user" do
    # Create applications with different configs
    default_rule = Application.create!(name: "Default App", slug: "default-app", app_type: "forward_auth", domain_pattern: "default.example.com", active: true)
    custom_rule = Application.create!(
      name: "Custom App", slug: "custom-app", app_type: "forward_auth",
      domain_pattern: "custom.example.com",
      active: true,
      metadata: { headers: { user: "X-WEBAUTH-USER", groups: "X-WEBAUTH-ROLES" } }.to_json
    )
    no_headers_rule = Application.create!(
      name: "No Headers App", slug: "no-headers-app", app_type: "forward_auth",
      domain_pattern: "noheaders.example.com",
      active: true,
      metadata: { headers: { user: "", email: "", name: "", groups: "", admin: "" } }.to_json
    )

    # Add user to groups
    @user.groups << @group
    @user.groups << @group2

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test default headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "default.example.com" }
    assert_response 200
    assert_equal "X-Remote-User", response.headers.keys.find { |k| k.include?("User") }
    assert_equal "X-Remote-Groups", response.headers.keys.find { |k| k.include?("Groups") }

    # Test custom headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "custom.example.com" }
    assert_response 200
    assert_equal "X-WEBAUTH-USER", response.headers.keys.find { |k| k.include?("USER") }
    assert_equal "X-WEBAUTH-ROLES", response.headers.keys.find { |k| k.include?("ROLES") }

    # Test no headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "noheaders.example.com" }
    assert_response 200
    auth_headers = response.headers.select { |k, v| k.match?(/^(X-|Remote-)/i) }
    assert_empty auth_headers
  end

  # Redirect URL Integration Tests
  test "redirect URL preserves original request information" do
    # Test with various redirect parameters
    test_cases = [
      { rd: "https://app.example.com/", rm: "GET" },
      { rd: "https://grafana.example.com/dashboard", rm: "POST" },
      { rd: "https://metube.example.com/videos", rm: "PUT" }
    ]

    test_cases.each do |params|
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }, params: params

      assert_response 302
      location = response.location

      # Should contain the original redirect URL
      assert_includes location, params[:rd]
      assert_includes location, params[:rm]
      assert_includes location, "/signin"
    end
  end

  test "return URL functionality after authentication" do
    # Initial request should set return URL
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "test.example.com",
      "X-Forwarded-Uri" => "/admin"
    }, params: { rd: "https://app.example.com/admin" }

    assert_response 302
    location = response.location

    # Extract return URL from location
    assert_match /rd=([^&]+)/, location
    return_url = CGI.unescape($1)
    assert_equal "https://app.example.com/admin", return_url

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
      domain_pattern: "admin.example.com",
      active: true,
      headers_config: { user: "X-Admin-User", admin: "X-Admin-Flag" }
    )

    # Test regular user
    post "/signin", params: { email_address: regular_user.email_address, password: "password" }
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    assert_equal regular_user.email_address, response.headers["X-Admin-User"]

    # Sign out
    delete "/session"

    # Test admin user
    post "/signin", params: { email_address: admin_user.email_address, password: "password" }
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    assert_equal admin_user.email_address, response.headers["X-Admin-User"]
    assert_equal "true", response.headers["X-Admin-Flag"]
  end

  # Security Integration Tests
  test "session hijacking prevention" do
    # User A signs in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    user_a_session = cookies[:session_id]

    # User B signs in
    delete "/session"
    post "/signin", params: { email_address: @admin_user.email_address, password: "password" }
    user_b_session = cookies[:session_id]

    # User A's session should still work
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "test.example.com",
      "Cookie" => "_clinch_session_id=#{user_a_session}"
    }
    assert_response 200
    assert_equal @user.email_address, response.headers["X-Remote-User"]

    # User B's session should work
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "test.example.com",
      "Cookie" => "_clinch_session_id=#{user_b_session}"
    }
    assert_response 200
    assert_equal @admin_user.email_address, response.headers["X-Remote-User"]
  end

  test "concurrent requests with same session" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    session_cookie = cookies[:session_id]

    # Simulate concurrent requests
    threads = []
    results = []

    5.times do |i|
      threads << Thread.new do
        # Create a new integration test instance for this thread
        test_instance = self.class.new
        test_instance.setup_controller_request_and_response

        test_instance.get "/api/verify", headers: {
          "X-Forwarded-Host" => "app#{i}.example.com",
          "Cookie" => "_clinch_session_id=#{session_cookie}"
        }

        results << {
          thread_id: i,
          status: test_instance.response.status,
          user: test_instance.response.headers["X-Remote-User"]
        }
      end
    end

    threads.each(&:join)

    # All requests should succeed
    results.each do |result|
      assert_equal 200, result[:status], "Thread #{result[:thread_id]} failed"
      assert_equal @user.email_address, result[:user], "Thread #{result[:thread_id]} has wrong user"
    end
  end

  # Performance Integration Tests
  test "response times are reasonable" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test multiple requests
    start_time = Time.current

    10.times do |i|
      get "/api/verify", headers: { "X-Forwarded-Host" => "app#{i}.example.com" }
      assert_response 200
    end

    end_time = Time.current
    total_time = end_time - start_time
    average_time = total_time / 10

    # Each request should take less than 100ms on average
    assert average_time < 0.1, "Average response time #{average_time}s is too slow"
  end

  # Error Handling Integration Tests
  test "graceful handling of malformed headers" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    # Test various malformed header combinations
    test_cases = [
      { "X-Forwarded-Host" => nil },
      { "X-Forwarded-Host" => "" },
      { "X-Forwarded-Host" => "   " },
      { "Host" => nil },
      { "Host" => "" }
    ]

    test_cases.each_with_index do |headers, i|
      get "/api/verify", headers: headers
      assert_response 200, "Failed on test case #{i}: #{headers.inspect}"
    end
  end
end