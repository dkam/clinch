require "test_helper"

class OidcAuthorizationCodeSecurityTest < ActionDispatch::IntegrationTest
  def setup
    @user = User.create!(email_address: "security_test@example.com", password: "password123")
    @application = Application.create!(
      name: "Security Test App",
      slug: "security-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )

    # Store the plain text client secret for testing
    @client_secret = @application.client_secret_digest
    @application.generate_new_client_secret!
    @plain_client_secret = @application.client_secret
    @application.save!
  end

  def teardown
    OidcAuthorizationCode.where(application: @application).destroy_all
    OidcAccessToken.where(application: @application).destroy_all
    @user.destroy
    @application.destroy
  end

  # ====================
  # CRITICAL SECURITY TESTS
  # ====================

  test "prevents authorization code reuse - sequential attempts" do
    # Create a valid authorization code
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    # First request should succeed
    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    first_response = JSON.parse(@response.body)
    assert first_response.key?("access_token")
    assert first_response.key?("id_token")

    # Second request with same code should fail
    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
    assert_match(/already been used/, error["error_description"])
  end

  test "revokes existing tokens when authorization code is reused" do
    # Create a valid authorization code
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    # First request - get access token
    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    first_response = JSON.parse(@response.body)
    first_access_token = first_response["access_token"]

    # Verify the token works
    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{first_access_token}"
    }
    assert_response :success

    # Second request with same code - should fail AND revoke first token
    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request

    # Verify the first token is now revoked (expired)
    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{first_access_token}"
    }
    assert_response :unauthorized, "First access token should be revoked after code reuse"
  end

  test "rejects already used authorization code" do
    # Create and mark code as used
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      used: true,
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
    assert_match(/already been used/, error["error_description"])
  end

  test "rejects expired authorization code" do
    # Create expired code
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 5.minutes.ago
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
    assert_match(/expired/, error["error_description"])
  end

  test "rejects authorization code with mismatched redirect_uri" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://evil.com/callback" # Wrong redirect URI
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
    assert_match(/Redirect URI mismatch/, error["error_description"])
  end

  test "rejects non-existent authorization code" do
    token_params = {
      grant_type: "authorization_code",
      code: "nonexistent_code_12345",
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
  end

  test "rejects authorization code for different application" do
    # Create another application
    other_app = Application.create!(
      name: "Other App",
      slug: "other-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:5000/callback"].to_json,
      active: true
    )
    other_secret = other_app.client_secret

    # Create auth code for first application
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Try to use it with different application credentials
    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{other_app.client_id}:#{other_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]

    other_app.destroy
  end

  # ====================
  # CLIENT AUTHENTICATION TESTS
  # ====================

  test "rejects invalid client_id in Basic auth" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("invalid_client_id:#{@plain_client_secret}")
    }

    assert_response :unauthorized
    error = JSON.parse(@response.body)
    assert_equal "invalid_client", error["error"]
  end

  test "rejects invalid client_secret in Basic auth" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:wrong_secret")
    }

    assert_response :unauthorized
    error = JSON.parse(@response.body)
    assert_equal "invalid_client", error["error"]
  end

  test "accepts client credentials in POST body" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      client_id: @application.client_id,
      client_secret: @plain_client_secret
    }

    post "/oauth/token", params: token_params

    assert_response :success
    response_body = JSON.parse(@response.body)
    assert response_body.key?("access_token")
    assert response_body.key?("id_token")
  end

  test "rejects request with no client authentication" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params

    assert_response :unauthorized
    error = JSON.parse(@response.body)
    assert_equal "invalid_client", error["error"]
  end

  # ====================
  # GRANT TYPE VALIDATION
  # ====================

  test "rejects unsupported grant_type" do
    post "/oauth/token", params: {
      grant_type: "password",
      username: "user",
      password: "pass"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "unsupported_grant_type", error["error"]
  end

  test "rejects missing grant_type" do
    post "/oauth/token", params: {
      code: "some_code",
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "unsupported_grant_type", error["error"]
  end

  # ====================
  # TIMING ATTACK PROTECTION
  # ====================

  test "client authentication uses constant-time comparison" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    # Test with completely wrong secret
    times_wrong = []
    5.times do
      start_time = Time.now.to_f
      post "/oauth/token", params: token_params, headers: {
        "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:wrong_secret_xxx")
      }
      times_wrong << (Time.now.to_f - start_time)
      assert_response :unauthorized
    end

    # Test with almost correct secret (differs by one character)
    correct_secret = @plain_client_secret
    almost_correct = correct_secret[0..-2] + "X"

    times_almost = []
    5.times do
      start_time = Time.now.to_f
      post "/oauth/token", params: token_params, headers: {
        "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{almost_correct}")
      }
      times_almost << (Time.now.to_f - start_time)
      assert_response :unauthorized
    end

    # The timing difference should be minimal (within 50ms) if using constant-time comparison
    avg_wrong = times_wrong.sum / times_wrong.size
    avg_almost = times_almost.sum / times_almost.size
    timing_difference = (avg_wrong - avg_almost).abs

    # This is a best-effort check - in practice, constant-time comparison is handled by bcrypt
    assert timing_difference < 0.05,
      "Timing difference #{timing_difference}s suggests potential timing attack vulnerability"
  end
end
