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
    OidcAuthorizationCode.where(application: @application).destroy_all
    OidcAccessToken.where(application: @application).destroy_all
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
    # Create authorization code without PKCE
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
      "Authorization" => "Basic " + Base64.strict_encode64("#{@application.client_id}:#{@application.client_secret}")
    }

    assert_response :success
    tokens = JSON.parse(@response.body)
    assert tokens.key?("access_token")
    assert tokens.key?("id_token")
    assert_equal "Bearer", tokens["token_type"]
  end
end