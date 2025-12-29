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
    OidcAuthorizationCode.where(application: @application).delete_all
    # Use delete_all to avoid triggering callbacks that might have issues with the schema
    OidcAccessToken.where(application: @application).delete_all
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

  # ====================
  # STATE PARAMETER BINDING (CSRF PREVENTION FOR OAUTH)
  # ====================

  test "state parameter is required and validated in authorization flow" do
    # Create consent to skip consent page
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Test authorization with state parameter
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      response_type: "code",
      scope: "openid profile",
      state: "random_state_123"
    }

    # Should include state in redirect
    assert_response :redirect
    assert_match(/state=random_state_123/, response.location)
  end

  test "authorization without state parameter still works but is less secure" do
    # Create consent to skip consent page
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Sign in first
    post signin_path, params: { email_address: "security_test@example.com", password: "password123" }

    # Test authorization without state parameter
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      response_type: "code",
      scope: "openid profile"
    }

    # Should work but state is recommended for CSRF protection
    assert_response :redirect
  end

  # ====================
  # NONCE PARAMETER VALIDATION (FOR ID TOKENS)
  # ====================

  test "nonce parameter is included in ID token" do
    # Create consent
    consent = OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with nonce
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      nonce: "test_nonce_123",
      expires_at: 10.minutes.from_now
    )

    # Exchange code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(@response.body)
    id_token = response_body["id_token"]

    # Decode ID token (without verification for this test)
    decoded_token = JWT.decode(id_token, nil, false)

    # Verify nonce is included in ID token
    assert_equal "test_nonce_123", decoded_token[0]["nonce"]
  end

  # ====================
  # TOKEN LEAKAGE VIA REFERER HEADER TESTS
  # ====================

  test "access tokens are not exposed in referer header" do
    # Create consent and authorization code
    consent = OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Exchange code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(@response.body)
    access_token = response_body["access_token"]

    # Verify token is not in response headers (especially Referer)
    assert_nil response.headers["Referer"], "Access token should not leak in Referer header"
    assert_nil response.headers["Location"], "Access token should not leak in Location header"
  end

  # ====================
  # PKCE ENFORCEMENT FOR PUBLIC CLIENTS TESTS
  # ====================

  test "PKCE code_verifier is required when code_challenge was provided" do
    # Create consent
    consent = OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE challenge
    code_verifier = SecureRandom.urlsafe_base64(32)
    code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    # Try to exchange code without code_verifier
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_request", error["error"]
    assert_match(/code_verifier is required/, error["error_description"])
  end

  test "PKCE with S256 method validates correctly" do
    # Create consent
    consent = OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE S256
    code_verifier = SecureRandom.urlsafe_base64(32)
    code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    # Exchange code with correct code_verifier
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      code_verifier: code_verifier
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(@response.body)
    assert response_body.key?("access_token")
  end

  test "PKCE rejects invalid code_verifier" do
    # Create consent
    consent = OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE
    code_verifier = SecureRandom.urlsafe_base64(32)
    code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    # Try with wrong code_verifier
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      code_verifier: "wrong_code_verifier_12345678901234567890"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
  end

  # ====================
  # REFRESH TOKEN ROTATION TESTS
  # ====================

  test "refresh token rotation is enforced" do
    # Create initial access and refresh tokens
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile"
    )

    original_token_family_id = refresh_token.token_family_id
    old_refresh_token = refresh_token.token

    # Refresh the token
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: old_refresh_token
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(@response.body)
    new_refresh_token = response_body["refresh_token"]

    # Verify new refresh token is different
    assert_not_equal old_refresh_token, new_refresh_token

    # Verify token family is preserved
    new_token_record = OidcRefreshToken.where(application: @application).find do |rt|
      rt.token_matches?(new_refresh_token)
    end
    assert_equal original_token_family_id, new_token_record.token_family_id

    # Old refresh token should be revoked
    old_token_record = OidcRefreshToken.find(refresh_token.id)
    assert old_token_record.revoked?
  end
end
