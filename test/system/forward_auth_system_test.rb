require "test_helper"

class ForwardAuthSystemTest < ActionDispatch::SystemTestCase
  driven_by :rack_test

  setup do
    @user = users(:one)
    @admin_user = users(:two)
    @group = groups(:one)
    @group2 = groups(:two)
  end

  # End-to-End Authentication Flow Tests
  test "complete forward auth flow with default headers" do
    # Create an application with default headers
    rule = Application.create!(name: "App", slug: "app-system-test", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)

    # Step 1: Unauthenticated request to protected resource
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "app.example.com",
      "X-Forwarded-Uri" => "/dashboard"
    }, params: { rd: "https://app.example.com/dashboard" }

    assert_response 302
    location = response.location
    assert_match %r{/signin}, location
    assert_match %r{rd=https://app.example.com/dashboard}, location

    # Step 2: Extract return URL from session
    assert_equal "https://app.example.com/dashboard", session[:return_to_after_authenticating]

    # Step 3: Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }

    assert_response 302
    assert_redirected_to "https://app.example.com/dashboard"

    # Step 4: Authenticated request to protected resource
    get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }

    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
    assert_equal @user.email_address, response.headers["x-remote-email"]
    assert_equal "false", response.headers["x-remote-admin"] unless @user.admin?
  end

  test "multiple domain access with single session" do
    # Create applications for different domains
    app_rule = Application.create!(name: "App Domain", slug: "app-domain", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)
    grafana_rule = Application.create!(
      name: "Grafana", slug: "grafana-system-test", app_type: "forward_auth",
      domain_pattern: "grafana.example.com",
      active: true,
      headers_config: { user: "X-WEBAUTH-USER", email: "X-WEBAUTH-EMAIL" }
    )
    metube_rule = Application.create!(
      name: "Metube", slug: "metube-system-test", app_type: "forward_auth",
      domain_pattern: "metube.example.com",
      active: true,
      headers_config: { user: "", email: "", name: "", groups: "", admin: "" }
    )

    # Sign in once
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302
    assert_redirected_to "/"

    # Test access to different applications
    # App with default headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "app.example.com" }
    assert_response 200
    assert response.headers.key?("x-remote-user")

    # Grafana with custom headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "grafana.example.com" }
    assert_response 200
    assert response.headers.key?("x-webauth-user")

    # Metube with no headers
    get "/api/verify", headers: { "X-Forwarded-Host" => "metube.example.com" }
    assert_response 200
    auth_headers = response.headers.select { |k, v| k.match?(/^x-remote-|^x-webauth-|^x-admin-/i) }
    assert_empty auth_headers
  end

  # Group-Based Access Control System Tests
  test "group-based access control with multiple groups" do
    # Create restricted application
    restricted_rule = Application.create!(
      name: "Admin", slug: "admin-system-test", app_type: "forward_auth",
      domain_pattern: "admin.example.com",
      active: true
    )
    restricted_rule.allowed_groups << @group
    restricted_rule.allowed_groups << @group2

    # Add user to first group only
    @user.groups << @group

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302

    # Should have access (in allowed group)
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    assert_equal @group.name, response.headers["x-remote-groups"]

    # Add user to second group
    @user.groups << @group2

    # Should show multiple groups
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 200
    groups_header = response.headers["x-remote-groups"]
    assert_includes groups_header, @group.name
    assert_includes groups_header, @group2.name

    # Remove user from all groups
    @user.groups.clear

    # Should be denied
    get "/api/verify", headers: { "X-Forwarded-Host" => "admin.example.com" }
    assert_response 403
  end

  test "bypass mode when no groups assigned to rule" do
    # Create bypass application (no groups)
    bypass_rule = Application.create!(
      name: "Public", slug: "public-system-test", app_type: "forward_auth",
      domain_pattern: "public.example.com",
      active: true
    )

    # Create user with no groups
    @user.groups.clear

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302

    # Should have access (bypass mode)
    get "/api/verify", headers: { "X-Forwarded-Host" => "public.example.com" }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]
  end

  # Security System Tests
  test "session security and isolation" do
    # User A signs in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    user_a_session = cookies[:session_id]

    # User B signs in
    delete "/session"
    post "/signin", params: { email_address: @admin_user.email_address, password: "password" }
    user_b_session = cookies[:session_id]

    # User A should still be able to access resources
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "test.example.com",
      "Cookie" => "_clinch_session_id=#{user_a_session}"
    }
    assert_response 200
    assert_equal @user.email_address, response.headers["x-remote-user"]

    # User B should be able to access resources
    get "/api/verify", headers: {
      "X-Forwarded-Host" => "test.example.com",
      "Cookie" => "_clinch_session_id=#{user_b_session}"
    }
    assert_response 200
    assert_equal @admin_user.email_address, response.headers["x-remote-user"]

    # Sessions should be independent
    assert_not_equal user_a_session, user_b_session
  end

  test "session expiration and cleanup" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    session_id = cookies[:session_id]

    # Should work initially
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200

    # Manually expire session
    session = Session.find(session_id)
    session.update!(expires_at: 1.hour.ago)

    # Should redirect to login
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 302
    assert_equal "Session expired", response.headers["x-auth-reason"]

    # Session should be cleaned up
    assert_nil Session.find_by(id: session_id)
  end

  test "concurrent access with rate limiting considerations" do
    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    session_cookie = cookies[:session_id]

    # Simulate multiple concurrent requests from different IPs
    threads = []
    results = []

    10.times do |i|
      threads << Thread.new do
        start_time = Time.current

        get "/api/verify", headers: {
          "X-Forwarded-Host" => "app#{i}.example.com",
          "X-Forwarded-For" => "192.168.1.#{100 + i}",
          "Cookie" => "_clinch_session_id=#{session_cookie}"
        }

        end_time = Time.current

        results << {
          thread_id: i,
          status: response.status,
          user: response.headers["x-remote-user"],
          duration: end_time - start_time
        }
      end
    end

    threads.each(&:join)

    # All requests should succeed
    results.each do |result|
      assert_equal 200, result[:status], "Thread #{result[:thread_id]} failed"
      assert_equal @user.email_address, result[:user], "Thread #{result[:thread_id]} has wrong user"
      assert result[:duration] < 1.0, "Thread #{result[:thread_id]} was too slow"
    end
  end

  # Complex Scenario System Tests
  test "complex multi-application scenario" do
    # Setup multiple applications with different requirements
    apps = [
      {
        domain: "dashboard.example.com",
        headers_config: { user: "X-DASHBOARD-USER", groups: "X-DASHBOARD-GROUPS" },
        groups: [@group]
      },
      {
        domain: "api.example.com",
        headers_config: { user: "X-API-USER", email: "X-API-EMAIL" },
        groups: []
      },
      {
        domain: "logs.example.com",
        headers_config: { user: "", email: "", name: "", groups: "", admin: "" },
        groups: []
      }
    ]

    # Create applications for each app
    rules = apps.map.with_index do |app, idx|
      rule = Application.create!(
        name: "Multi App #{idx}", slug: "multi-app-#{idx}", app_type: "forward_auth",
        domain_pattern: app[:domain],
        active: true,
        headers_config: app[:headers_config]
      )
      app[:groups].each { |group| rule.allowed_groups << group }
      rule
    end

    # Add user to required groups
    @user.groups << @group

    # Sign in once
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302

    # Test access to each application
    apps.each do |app|
      get "/api/verify", headers: { "X-Forwarded-Host" => app[:domain] }
      assert_response 200, "Failed for #{app[:domain]}"

      # Verify headers are correct
      if app[:headers_config][:user].present?
        assert_equal app[:headers_config][:user],
                     response.headers.keys.find { |k| k.include?("USER") },
                     "Wrong user header for #{app[:domain]}"
        assert_equal @user.email_address, response.headers[app[:headers_config][:user]]
      else
        # Should have no auth headers
        auth_headers = response.headers.select { |k, v| k.match?(/^(X-|Remote-)/i) }
        assert_empty auth_headers, "Should have no headers for #{app[:domain]}"
      end
    end
  end

  test "domain pattern edge cases" do
    # Test various domain patterns
    patterns = [
      { pattern: "*.example.com", domains: ["app.example.com", "api.example.com", "sub.app.example.com"] },
      { pattern: "api.*.com", domains: ["api.example.com", "api.test.com"] },
      { pattern: "*.*.example.com", domains: ["app.dev.example.com", "api.staging.example.com"] }
    ]

    patterns.each_with_index do |pattern_config, idx|
      rule = Application.create!(
        name: "Pattern Test #{idx}", slug: "pattern-test-#{idx}", app_type: "forward_auth",
        domain_pattern: pattern_config[:pattern],
        active: true
      )

      # Sign in
      post "/signin", params: { email_address: @user.email_address, password: "password" }

      # Test each domain
      pattern_config[:domains].each do |domain|
        get "/api/verify", headers: { "X-Forwarded-Host" => domain }
        assert_response 200, "Failed for pattern #{pattern_config[:pattern]} with domain #{domain}"
        assert_equal @user.email_address, response.headers["x-remote-user"]
      end

      # Clean up for next test
      delete "/session"
    end
  end

  # Performance System Tests
  test "system performance under load" do
    # Create test application
    rule = Application.create!(name: "Load Test", slug: "loadtest", app_type: "forward_auth", domain_pattern: "loadtest.example.com", active: true)

    # Sign in
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    session_cookie = cookies[:session_id]

    # Performance test
    start_time = Time.current
    request_count = 50
    results = []

    request_count.times do |i|
      request_start = Time.current

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "app#{i}.loadtest.example.com",
        "Cookie" => "_clinch_session_id=#{session_cookie}"
      }

      request_end = Time.current

      results << {
        request_id: i,
        status: response.status,
        duration: request_end - request_start
      }
    end

    total_time = Time.current - start_time
    average_duration = results.map { |r| r[:duration] }.sum / request_count

    # Performance assertions
    assert total_time < 5.0, "Total time #{total_time}s is too slow"
    assert average_duration < 0.1, "Average request time #{average_duration}s is too slow"
    assert results.all? { |r| r[:status] == 200 }, "Some requests failed"

    # Calculate requests per second
    rps = request_count / total_time
    assert rps > 10, "Requests per second #{rps} is too low"
  end

  # Error Recovery System Tests
  test "graceful degradation with database issues" do
    # Sign in first
    post "/signin", params: { email_address: @user.email_address, password: "password" }
    assert_response 302

    # Simulate database connection issue by mocking
    original_method = Session.method(:find_by)

    # Mock database failure
    Session.define_singleton_method(:find_by) do |id|
      raise ActiveRecord::ConnectionNotEstablished, "Database connection lost"
    end

    begin
      # Request should handle the error gracefully
      get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }

      # Should return 302 (redirect to login) rather than 500 error
      assert_response 302, "Should gracefully handle database issues"
      assert_equal "Invalid session", response.headers["x-auth-reason"]
    ensure
      # Restore original method
      Session.define_singleton_method(:find_by, original_method)
    end

    # Normal operation should still work
    get "/api/verify", headers: { "X-Forwarded-Host" => "test.example.com" }
    assert_response 200
  end
end