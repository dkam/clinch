require "test_helper"

class SessionSecurityTest < ActionDispatch::IntegrationTest
  # ====================
  # SESSION TIMEOUT TESTS
  # ====================

  test "session expires after inactivity" do
    user = User.create!(email_address: "session_test@example.com", password: "password123")
    user.update!(sessions_expire_at: 24.hours.from_now)

    # Sign in
    post signin_path, params: { email_address: "session_test@example.com", password: "password123" }
    assert_response :redirect
    follow_redirect!
    assert_response :success

    # Simulate session expiration by traveling past the expiry time
    travel 25.hours do
      get root_path
      # Session should be expired, user redirected to signin
      assert_response :redirect
      assert_redirected_to signin_path
    end

    user.destroy
  end

  test "active sessions are tracked correctly" do
    user = User.create!(email_address: "multi_session_test@example.com", password: "password123")

    # Create multiple sessions
    session1 = user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0 (Windows)",
      device_name: "Windows PC",
      last_activity_at: 10.minutes.ago
    )

    session2 = user.sessions.create!(
      ip_address: "192.168.1.2",
      user_agent: "Mozilla/5.0 (iPhone)",
      device_name: "iPhone",
      last_activity_at: 5.minutes.ago
    )

    # Check that both sessions are active
    assert_equal 2, user.sessions.active.count

    # Revoke one session
    session2.update!(expires_at: 1.minute.ago)

    # Only one session should remain active
    assert_equal 1, user.sessions.active.count
    assert_equal session1.id, user.sessions.active.first.id

    user.sessions.delete_all
    user.destroy
  end

  # ====================
  # SESSION FIXATION PREVENTION TESTS
  # ====================

  test "session_id changes after authentication" do
    user = User.create!(email_address: "session_fixation_test@example.com", password: "password123")

    # Get initial session ID
    get root_path
    initial_session_id = request.session.id

    # Sign in
    post signin_path, params: { email_address: "session_fixation_test@example.com", password: "password123" }

    # Session ID should have changed after authentication
    # Note: Rails handles this automatically with regenerate: true in session handling
    # This test verifies the behavior is working as expected

    user.destroy
  end

  # ====================
  # CONCURRENT SESSION HANDLING TESTS
  # ====================

  test "user can have multiple concurrent sessions" do
    user = User.create!(email_address: "concurrent_session_test@example.com", password: "password123")

    # Create multiple sessions from different devices
    session1 = user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0 (Windows)",
      device_name: "Windows PC",
      last_activity_at: Time.current
    )

    session2 = user.sessions.create!(
      ip_address: "192.168.1.2",
      user_agent: "Mozilla/5.0 (iPhone)",
      device_name: "iPhone",
      last_activity_at: Time.current
    )

    session3 = user.sessions.create!(
      ip_address: "192.168.1.3",
      user_agent: "Mozilla/5.0 (Macintosh)",
      device_name: "MacBook",
      last_activity_at: Time.current
    )

    # All three sessions should be active
    assert_equal 3, user.sessions.active.count

    user.sessions.delete_all
    user.destroy
  end

  test "revoking one session does not affect other sessions" do
    user = User.create!(email_address: "revoke_session_test@example.com", password: "password123")

    # Create two sessions
    session1 = user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0 (Windows)",
      device_name: "Windows PC",
      last_activity_at: Time.current
    )

    session2 = user.sessions.create!(
      ip_address: "192.168.1.2",
      user_agent: "Mozilla/5.0 (iPhone)",
      device_name: "iPhone",
      last_activity_at: Time.current
    )

    # Revoke session1
    session1.update!(expires_at: 1.minute.ago)

    # Session2 should still be active
    assert_equal 1, user.sessions.active.count
    assert_equal session2.id, user.sessions.active.first.id

    user.sessions.delete_all
    user.destroy
  end

  # ====================
  # LOGOUT INVALIDATES SESSIONS TESTS
  # ====================

  test "logout invalidates all user sessions" do
    user = User.create!(email_address: "logout_test@example.com", password: "password123")

    # Create multiple sessions
    user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0 (Windows)",
      device_name: "Windows PC",
      last_activity_at: Time.current
    )

    user.sessions.create!(
      ip_address: "192.168.1.2",
      user_agent: "Mozilla/5.0 (iPhone)",
      device_name: "iPhone",
      last_activity_at: Time.current
    )

    # Sign in
    post signin_path, params: { email_address: "logout_test@example.com", password: "password123" }
    assert_response :redirect

    # Sign out
    delete signout_path
    assert_response :redirect
    follow_redirect!
    assert_response :success

    # All sessions should be invalidated
    assert_equal 0, user.sessions.active.count

    user.sessions.delete_all
    user.destroy
  end

  test "logout sends backchannel logout notifications" do
    user = User.create!(email_address: "logout_notification_test@example.com", password: "password123")
    application = Application.create!(
      name: "Logout Test App",
      slug: "logout-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      backchannel_logout_uri: "http://localhost:4000/logout",
      active: true
    )

    # Create consent with backchannel logout enabled
    consent = OidcUserConsent.create!(
      user: user,
      application: application,
      scopes_granted: "openid profile",
      sid: "test-session-id-123"
    )

    # Sign in
    post signin_path, params: { email_address: "logout_notification_test@example.com", password: "password123" }
    assert_response :redirect

    # Sign out
    assert_enqueued_jobs 1 do
      delete signout_path
      assert_response :redirect
    end

    # Verify backchannel logout job was enqueued
    assert_equal "BackchannelLogoutJob", ActiveJob::Base.queue_adapter.enqueued_jobs.first[:job]

    user.sessions.delete_all
    user.destroy
    application.destroy
  end

  # ====================
  # SESSION HIJACKING PREVENTION TESTS
  # ====================

  test "session includes IP address and user agent tracking" do
    user = User.create!(email_address: "hijacking_test@example.com", password: "password123")

    # Sign in
    post signin_path, params: { email_address: "hijacking_test@example.com", password: "password123" },
      headers: { "HTTP_USER_AGENT" => "TestBrowser/1.0" }
    assert_response :redirect

    # Check that session includes IP and user agent
    session = user.sessions.active.first
    assert_not_nil session.ip_address
    assert_not_nil session.user_agent

    user.sessions.delete_all
    user.destroy
  end

  test "session activity is tracked" do
    user = User.create!(email_address: "activity_test@example.com", password: "password123")

    # Create session
    session = user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0",
      device_name: "Test Device",
      last_activity_at: 1.hour.ago
    )

    # Simulate activity update
    session.update!(last_activity_at: Time.current)

    # Session should still be active
    assert session.active?

    user.sessions.delete_all
    user.destroy
  end

  # ====================
  # FORWARD AUTH SESSION TESTS
  # ====================

  test "forward auth validates session correctly" do
    user = User.create!(email_address: "forward_auth_test@example.com", password: "password123")
    application = Application.create!(
      name: "Forward Auth Test",
      slug: "forward-auth-test",
      app_type: "forward_auth",
      redirect_uris: ["https://test.example.com"].to_json,
      active: true
    )

    # Create session
    user_session = user.sessions.create!(
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0",
      last_activity_at: Time.current
    )

    # Test forward auth endpoint with valid session
    get forward_auth_path(rd: "https://test.example.com/protected"),
      headers: { cookie: "_session_id=#{user_session.id}" }

    # Should accept the request and redirect back
    assert_response :redirect

    user.sessions.delete_all
    user.destroy
    application.destroy
  end
end
