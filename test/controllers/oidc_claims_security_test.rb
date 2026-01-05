require "test_helper"

class OidcClaimsSecurityTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "claims_security_test@example.com", password: "password123")
    @application = Application.create!(
      name: "Claims Security Test App",
      slug: "claims-security-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true,
      require_pkce: false
    )

    # Store the plain text client secret for testing
    @application.generate_new_client_secret!
    @plain_client_secret = @application.client_secret
    @application.save!
  end

  def teardown
    # Delete in correct order to avoid foreign key constraints
    OidcRefreshToken.where(application: @application).delete_all
    OidcAccessToken.where(application: @application).delete_all
    OidcAuthorizationCode.where(application: @application).delete_all
    OidcUserConsent.where(application: @application).delete_all
    @user.destroy
    @application.destroy
  end

  # ====================
  # CLAIMS PARAMETER ESCALATION ATTACKS
  # ====================

  test "rejects claims parameter during authorization code exchange" do
    # Create consent with minimal scopes (no profile, email, or admin access)
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid",
      expires_at: 10.minutes.from_now
    )

    # ATTEMPT: Inject claims parameter during token exchange (ATTACK!)
    # The client is trying to request 'admin' claim that they never got consent for
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.plaintext_code,
      redirect_uri: "http://localhost:4000/callback",
      claims: '{"id_token":{"admin":{"essential":true}}}' # ← ATTACK!
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    # SHOULD: Reject the claims parameter - it's only allowed in authorization requests
    assert_response :bad_request
    error = JSON.parse(response.body)
    assert_equal "invalid_request", error["error"], "Should reject claims parameter at token endpoint"
    assert_match(/claims.*not allowed|unsupported parameter/i, error["error_description"], "Error should mention claims parameter not allowed")
  end

  test "rejects claims parameter during authorization code exchange with profile escalation" do
    # Create consent with ONLY openid scope (no profile scope)
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid",
      expires_at: 10.minutes.from_now
    )

    # ATTEMPT: Try to get profile claims via claims parameter without profile scope
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.plaintext_code,
      redirect_uri: "http://localhost:4000/callback",
      claims: '{"id_token":{"name":null,"email":{"essential":true}}}'
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    # SHOULD: Reject the claims parameter
    assert_response :bad_request
    error = JSON.parse(response.body)
    assert_equal "invalid_request", error["error"]
  end

  test "rejects claims parameter during refresh token grant" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid"
    )

    plaintext_refresh_token = refresh_token.token

    # ATTEMPT: Inject claims parameter during refresh (ATTACK!)
    # Trying to escalate to admin claims during refresh
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      claims: '{"id_token":{"admin":true,"role":{"essential":true}}}' # ← ATTACK!
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    # SHOULD: Reject the claims parameter
    assert_response :bad_request
    error = JSON.parse(response.body)
    assert_equal "invalid_request", error["error"], "Should reject claims parameter at refresh token endpoint"
    assert_match(/claims.*not allowed|unsupported parameter/i, error["error_description"])
  end

  test "rejects claims parameter during refresh token grant with custom claims escalation" do
    # Setup: User has a custom claim at user level
    @user.update!(custom_claims: {"role" => "user"})

    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid"
    )

    plaintext_refresh_token = refresh_token.token

    # ATTEMPT: Try to escalate role to admin via claims parameter
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      claims: '{"id_token":{"role":{"value":"admin"}}}' # ← ATTACK! Trying to override role value
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    # SHOULD: Reject the claims parameter
    assert_response :bad_request
    error = JSON.parse(response.body)
    assert_equal "invalid_request", error["error"]
  end

  test "allows token exchange without claims parameter" do
    # Create consent
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Normal token exchange WITHOUT claims parameter should work fine
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.plaintext_code,
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(response.body)
    assert response_body.key?("access_token")
    assert response_body.key?("id_token")
  end

  test "allows refresh without claims parameter" do
    # Create consent for this application
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-refresh-456"
    )

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

    plaintext_refresh_token = refresh_token.token

    # Normal refresh WITHOUT claims parameter should work fine
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(response.body)
    assert response_body.key?("access_token")
    assert response_body.key?("id_token")
  end

  # ====================
  # CLAIMS PARAMETER IS AUTHORIZATION-ONLY
  # ====================

  test "claims parameter is only valid in authorization request per OIDC spec" do
    # Per OIDC Core spec section 18.2.1, claims parameter usage location is "Authorization Request"
    # This test verifies that claims parameter cannot be used at token endpoint

    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid",
      expires_at: 10.minutes.from_now
    )

    # Test various attempts to inject claims parameter
    malicious_claims = [
      '{"id_token":{"admin":true}}',
      '{"id_token":{"email":{"essential":true}}}',
      '{"userinfo":{"groups":{"values":["admin"]}}}',
      '{"id_token":{"custom_claim":"custom_value"}}',
      'invalid-json'
    ]

    malicious_claims.each do |claims_value|
      post "/oauth/token", params: {
        grant_type: "authorization_code",
        code: auth_code.plaintext_code,
        redirect_uri: "http://localhost:4000/callback",
        claims: claims_value
      }, headers: {
        "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
      }

      # All should be rejected
      assert_response :bad_request, "Claims parameter '#{claims_value}' should be rejected"
      error = JSON.parse(response.body)
      assert_equal "invalid_request", error["error"]
    end
  end

  # ====================
  # VERIFY CONSENT-BASED ACCESS IS ENFORCED
  # ====================

  test "token endpoint respects scopes granted during authorization" do
    # Create consent with ONLY openid scope (no email, profile, etc.)
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid",
      expires_at: 10.minutes.from_now
    )

    # Exchange code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.plaintext_code,
      redirect_uri: "http://localhost:4000/callback"
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(response.body)
    id_token = response_body["id_token"]

    # Decode ID token to check claims
    decoded = JWT.decode(id_token, nil, false).first

    # Should only have required claims, not email/profile
    assert_includes decoded.keys, "iss"
    assert_includes decoded.keys, "sub"
    assert_includes decoded.keys, "aud"
    assert_includes decoded.keys, "exp"
    assert_includes decoded.keys, "iat"

    # Should NOT have claims that weren't consented to
    refute_includes decoded.keys, "email", "Should not include email without email scope"
    refute_includes decoded.keys, "email_verified", "Should not include email_verified without email scope"
    refute_includes decoded.keys, "name", "Should not include name without profile scope"
    refute_includes decoded.keys, "preferred_username", "Should not include preferred_username without profile scope"
  end

  test "refresh token preserves original scopes granted during authorization" do
    # Create consent with specific scopes
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid email",
      granted_at: Time.current,
      sid: "test-sid-refresh-123"
    )

    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid email"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid email"
    )

    plaintext_refresh_token = refresh_token.token

    # Refresh the token
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token
    }, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@plain_client_secret}")
    }

    assert_response :success
    response_body = JSON.parse(response.body)
    id_token = response_body["id_token"]

    # Decode ID token to verify scopes are preserved
    decoded = JWT.decode(id_token, nil, false).first

    # Should have email claims (from original consent)
    assert_includes decoded.keys, "email", "Should preserve email scope from original consent"
    assert_includes decoded.keys, "email_verified", "Should preserve email_verified scope from original consent"

    # Should NOT have profile claims (not in original consent)
    refute_includes decoded.keys, "name", "Should not add profile claims that weren't consented to"
    refute_includes decoded.keys, "preferred_username", "Should not add preferred_username that wasn't consented to"
  end
end
