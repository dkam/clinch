require "test_helper"

class OidcPkceControllerTest < ActionDispatch::IntegrationTest
  def setup
    @user = User.create!(email_address: "pkce_test@example.com", password: "password123")
    @application = Application.create!(
      name: "PKCE Test App",
      slug: "pkce-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )

    # Sign in the user using the test helper
    sign_in_as(@user)
  end

  def teardown
    Current.session&.destroy
    # Delete in correct order to avoid foreign key constraints
    OidcRefreshToken.where(application: @application).delete_all
    OidcAccessToken.where(application: @application).delete_all
    OidcAuthorizationCode.where(application: @application).delete_all
    OidcUserConsent.where(application: @application).delete_all
    @user.destroy
    @application.destroy
  end

  test "discovery endpoint includes PKCE support" do
    get "/.well-known/openid-configuration"

    assert_response :success
    config = JSON.parse(@response.body)

    assert config.key?("code_challenge_methods_supported")
    assert_includes config["code_challenge_methods_supported"], "S256"
    assert_includes config["code_challenge_methods_supported"], "plain"
  end

  test "authorization endpoint accepts PKCE parameters (S256)" do
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    auth_params = {
      response_type: "code",
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      state: "test_state",
      nonce: "test_nonce",
      code_challenge: code_challenge,
      code_challenge_method: "S256"
    }

    get "/oauth/authorize", params: auth_params

    # Should show consent page (user is already authenticated)
    assert_response :success
    assert_match /consent/, @response.body.downcase
  end

  test "authorization endpoint accepts PKCE parameters (plain)" do
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    auth_params = {
      response_type: "code",
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      state: "test_state",
      nonce: "test_nonce",
      code_challenge: code_challenge,
      code_challenge_method: "plain"
    }

    get "/oauth/authorize", params: auth_params

    # Should show consent page (user is already authenticated)
    assert_response :success
    assert_match /consent/, @response.body.downcase
  end

  test "authorization endpoint rejects invalid code_challenge_method" do
    auth_params = {
      response_type: "code",
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "invalid_method"
    }

    get "/oauth/authorize", params: auth_params

    assert_response :bad_request
    assert_match(/Invalid code_challenge_method/, @response.body)
  end

  test "authorization endpoint rejects invalid code_challenge format" do
    # Contains + character which is not base64url
    auth_params = {
      response_type: "code",
      client_id: @application.client_id,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "invalid+challenge",
      code_challenge_method: "S256"
    }

    get "/oauth/authorize", params: auth_params

    assert_response :bad_request
    assert_match(/Invalid code_challenge format/, @response.body)
  end

  test "token endpoint requires code_verifier when PKCE was used (S256)" do
    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE S256
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_request", error["error"]
    assert_match(/code_verifier is required/, error["error_description"])
  end

  test "token endpoint requires code_verifier when PKCE was used (plain)" do
    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE plain
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "plain",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_request", error["error"]
    assert_match(/code_verifier is required/, error["error_description"])
  end

  test "token endpoint rejects invalid code_verifier (S256)" do
    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code with PKCE S256
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      # Use a properly formatted but wrong verifier (43+ chars, base64url)
      code_verifier: "wrongverifier_with_enough_characters_base64url"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_grant", error["error"]
    assert_match(/Invalid code verifier/, error["error_description"])
  end

  test "token endpoint accepts valid code_verifier (S256)" do
    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Generate valid PKCE pair
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = Digest::SHA256.base64digest(code_verifier)
      .tr("+/", "-_")
      .tr("=", "")

    # Create authorization code with PKCE S256
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

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      code_verifier: code_verifier
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :success
    tokens = JSON.parse(@response.body)
    assert tokens.key?("access_token")
    assert tokens.key?("id_token")
    assert_equal "Bearer", tokens["token_type"]
  end

  test "token endpoint accepts valid code_verifier (plain)" do
    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    code_verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    # Create authorization code with PKCE plain
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_verifier, # Same as verifier for plain method
      code_challenge_method: "plain",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback",
      code_verifier: code_verifier
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :success
    tokens = JSON.parse(@response.body)
    assert tokens.key?("access_token")
    assert tokens.key?("id_token")
    assert_equal "Bearer", tokens["token_type"]
  end

  test "token endpoint works without PKCE (backward compatibility)" do
    # Create an application with PKCE not required (legacy behavior)
    legacy_app = Application.create!(
      name: "Legacy App",
      slug: "legacy-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:5000/callback"].to_json,
      active: true,
      require_pkce: false
    )
    legacy_app.generate_new_client_secret!

    # Create consent for token endpoint
    OidcUserConsent.create!(
      user: @user,
      application: legacy_app,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code without PKCE
    auth_code = OidcAuthorizationCode.create!(
      application: legacy_app,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:5000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:5000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{legacy_app.client_id}:#{legacy_app.client_secret}")
    }

    assert_response :success
    tokens = JSON.parse(@response.body)
    assert tokens.key?("access_token")
    assert tokens.key?("id_token")
    assert_equal "Bearer", tokens["token_type"]

    # Cleanup
    OidcRefreshToken.where(application: legacy_app).delete_all
    OidcAccessToken.where(application: legacy_app).delete_all
    OidcAuthorizationCode.where(application: legacy_app).delete_all
    OidcUserConsent.where(application: legacy_app).delete_all
    legacy_app.destroy
  end

  # ====================
  # PUBLIC CLIENT TESTS
  # ====================

  test "public client can authenticate with PKCE" do
    # Create a public client (no client_secret)
    public_app = Application.create!(
      name: "Public App",
      slug: "public-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:6000/callback"].to_json,
      active: true,
      is_public_client: true
    )

    assert public_app.public_client?
    assert public_app.requires_pkce?
    assert_nil public_app.client_secret_digest

    # Create consent
    OidcUserConsent.create!(
      user: @user,
      application: public_app,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # PKCE parameters
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    # Create authorization code with PKCE
    auth_code = OidcAuthorizationCode.create!(
      application: public_app,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:6000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now,
      code_challenge: code_challenge,
      code_challenge_method: "S256"
    )

    # Token request with PKCE but no client_secret
    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:6000/callback",
      client_id: public_app.client_id,
      code_verifier: code_verifier
    }

    post "/oauth/token", params: token_params

    assert_response :success
    tokens = JSON.parse(@response.body)
    assert tokens.key?("access_token")
    assert tokens.key?("id_token")

    # Cleanup
    OidcRefreshToken.where(application: public_app).delete_all
    OidcAccessToken.where(application: public_app).delete_all
    OidcAuthorizationCode.where(application: public_app).delete_all
    OidcUserConsent.where(application: public_app).delete_all
    public_app.destroy
  end

  test "public client fails without PKCE" do
    # Create a public client (no client_secret)
    public_app = Application.create!(
      name: "Public App No PKCE",
      slug: "public-app-no-pkce",
      app_type: "oidc",
      redirect_uris: ["http://localhost:7000/callback"].to_json,
      active: true,
      is_public_client: true
    )

    assert public_app.public_client?
    assert public_app.requires_pkce?

    # Create consent
    OidcUserConsent.create!(
      user: @user,
      application: public_app,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-123"
    )

    # Create authorization code WITHOUT PKCE
    auth_code = OidcAuthorizationCode.create!(
      application: public_app,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:7000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Token request without PKCE should fail
    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:7000/callback",
      client_id: public_app.client_id
    }

    post "/oauth/token", params: token_params

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_request", error["error"]
    assert_match /PKCE is required for public clients/, error["error_description"]

    # Cleanup
    OidcRefreshToken.where(application: public_app).delete_all
    OidcAccessToken.where(application: public_app).delete_all
    OidcAuthorizationCode.where(application: public_app).delete_all
    OidcUserConsent.where(application: public_app).delete_all
    public_app.destroy
  end

  test "confidential client with require_pkce fails without PKCE" do
    # The default @application has require_pkce: true (default)
    assert @application.confidential_client?
    assert @application.requires_pkce?

    # Create consent
    OidcUserConsent.create!(
      user: @user,
      application: @application,
      scopes_granted: "openid profile",
      granted_at: Time.current,
      sid: "test-sid-pkce-required"
    )

    # Create authorization code WITHOUT PKCE
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      code: SecureRandom.urlsafe_base64(32),
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Token request without PKCE should fail
    token_params = {
      grant_type: "authorization_code",
      code: auth_code.code,
      redirect_uri: "http://localhost:4000/callback"
    }

    post "/oauth/token", params: token_params, headers: {
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :bad_request
    error = JSON.parse(@response.body)
    assert_equal "invalid_request", error["error"]
    assert_match /PKCE is required/, error["error_description"]
  end
end