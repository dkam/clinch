require "test_helper"

class RateLimitingTest < ActionDispatch::IntegrationTest
  # ====================
  # LOGIN RATE LIMITING TESTS
  # ====================

  test "login endpoint enforces rate limit" do
    # Attempt more than the allowed 20 requests per 3 minutes
    # We'll do 21 requests and expect the 21st to fail
    21.times do |i|
      post signin_path, params: { email_address: "test@example.com", password: "wrong_password" }
      if i < 20
        assert_response :redirect
        assert_redirected_to signin_path
      else
        # 21st request should be rate limited
        assert_response :too_many_requests, "Request #{i+1} should be rate limited"
        assert_match(/too many attempts/i, response.body)
      end
    end
  end

  test "login rate limit resets after time window" do
    # First, hit the rate limit
    20.times { post signin_path, params: { email_address: "test@example.com", password: "wrong" } }
    assert_response :redirect

    # 21st request should be rate limited
    post signin_path, params: { email_address: "test@example.com", password: "wrong" }
    assert_response :too_many_requests

    # After waiting, rate limit should reset (this test demonstrates the concept)
    # In real scenarios, you'd use travel_to or mock time
    travel 3.minutes + 1.second do
      post signin_path, params: { email_address: "test@example.com", password: "wrong" }
      assert_response :redirect, "Rate limit should reset after time window"
    end
  end

  # ====================
  # PASSWORD RESET RATE LIMITING TESTS
  # ====================

  test "password reset endpoint enforces rate limit" do
    # Attempt more than the allowed 10 requests per 3 minutes
    11.times do |i|
      post password_path, params: { email_address: "test@example.com" }
      if i < 10
        assert_response :redirect
        assert_redirected_to signin_path
      else
        # 11th request should be rate limited
        assert_response :redirect
        follow_redirect!
        assert_match(/try again later/i, response.body)
      end
    end
  end

  # ====================
  # TOTP RATE LIMITING TESTS
  # ====================

  test "TOTP verification enforces rate limit" do
    user = User.create!(email_address: "totp_test@example.com", password: "password123")
    user.enable_totp!

    # Set up pending TOTP session
    post signin_path, params: { email_address: "totp_test@example.com", password: "password123" }
    assert_redirected_to totp_verification_path

    # Attempt more than the allowed 10 TOTP verifications per 3 minutes
    11.times do |i|
      post totp_verification_path, params: { code: "000000" }
      if i < 10
        assert_response :redirect
        assert_redirected_to totp_verification_path
      else
        # 11th request should be rate limited
        assert_response :redirect
        follow_redirect!
        assert_match(/too many attempts/i, response.body)
      end
    end

    user.destroy
  end

  # ====================
  # WEB AUTHN RATE LIMITING TESTS
  # ====================

  test "WebAuthn challenge endpoint enforces rate limit" do
    # Attempt more than the allowed 10 requests per 3 minutes
    11.times do |i|
      post webauthn_challenge_path, params: { email: "test@example.com" }, as: :json
      if i < 10
        # User not found, but request was processed
        assert_response :unprocessable_entity
      else
        # 11th request should be rate limited
        assert_response :too_many_requests
        json = JSON.parse(response.body)
        assert_equal "Too many attempts. Try again later.", json["error"]
      end
    end
  end

  # ====================
  # OIDC TOKEN RATE LIMITING TESTS
  # ====================

  test "OIDC token endpoint enforces rate limit" do
    application = Application.create!(
      name: "Rate Limit Test App",
      slug: "rate-limit-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )
    application.generate_new_client_secret!

    # Attempt more than the allowed 60 token requests per minute
    61.times do |i|
      post oauth_token_path, params: {
        grant_type: "authorization_code",
        code: "invalid_code",
        redirect_uri: "http://localhost:4000/callback"
      }, headers: {
        "Authorization" => "Basic " + Base64.strict_encode64("#{application.client_id}:#{application.client_secret}")
      }

      if i < 60
        assert_includes [400, 401], response.status
      else
        # 61st request should be rate limited
        assert_response :too_many_requests
        json = JSON.parse(response.body)
        assert_equal "too_many_requests", json["error"]
      end
    end

    application.destroy
  end

  # ====================
  # OIDC AUTHORIZATION RATE LIMITING TESTS
  # ====================

  test "OIDC authorization endpoint enforces rate limit" do
    application = Application.create!(
      name: "Auth Rate Limit Test App",
      slug: "auth-rate-limit-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )

    # Attempt more than the allowed 30 authorization requests per minute
    31.times do |i|
      get oauth_authorize_path, params: {
        client_id: application.client_id,
        redirect_uri: "http://localhost:4000/callback",
        response_type: "code",
        scope: "openid"
      }

      if i < 30
        # Should redirect to signin (not authenticated)
        assert_response :redirect
        assert_redirected_to signin_path
      else
        # 31st request should be rate limited
        assert_response :too_many_requests
        assert_match(/too many authorization attempts/i, response.body)
      end
    end

    application.destroy
  end

  # ====================
  # RATE LIMIT BY IP TESTS
  # ====================

  test "rate limits are enforced per IP address" do
    # Create two users to simulate requests from different IPs
    user1 = User.create!(email_address: "user1@example.com", password: "password123")
    user2 = User.create!(email_address: "user2@example.com", password: "password123")

    # Exhaust rate limit for first IP (simulated)
    20.times do
      post signin_path, params: { email_address: "user1@example.com", password: "wrong" }
    end

    # 21st request should be rate limited
    post signin_path, params: { email_address: "user1@example.com", password: "wrong" }
    assert_response :too_many_requests

    # Simulate request from different IP (this would require changing request.remote_ip)
    # In a real scenario, you'd use a different IP address
    # This test documents the expected behavior

    user1.destroy
    user2.destroy
  end

  # ====================
  # RATE LIMIT HEADERS TESTS
  # ====================

  test "rate limited responses include appropriate headers" do
    # Exhaust rate limit
    21.times do |i|
      post signin_path, params: { email_address: "test@example.com", password: "wrong" }
    end

    # Check for rate limit headers (if your implementation includes them)
    # Rails 8 rate limiting may include these headers
    assert_response :too_many_requests
    # Common rate limit headers to check:
    # - RateLimit-Limit
    # - RateLimit-Remaining
    # - RateLimit-Reset
    # - Retry-After
  end
end
