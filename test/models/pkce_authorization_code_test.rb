require "test_helper"

class PkceAuthorizationCodeTest < ActiveSupport::TestCase
  def setup
    @user = User.create!(email_address: "pkce_test@example.com", password: "password123")
    @application = Application.create!(
      name: "PKCE Test App",
      slug: "pkce-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )
  end

  def teardown
    # Clean up any authorization codes first to avoid foreign key constraints
    OidcAuthorizationCode.where(application: @application).destroy_all
    @user.destroy
    @application.destroy
  end

  test "authorization code can store PKCE challenge with S256 method" do
    code_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge_method = "S256"

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method,
      expires_at: 10.minutes.from_now
    )

    assert_equal code_challenge, auth_code.code_challenge
    assert_equal code_challenge_method, auth_code.code_challenge_method
    assert auth_code.uses_pkce?
  end

  test "authorization code can store PKCE challenge with plain method" do
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    code_challenge_method = "plain"

    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method,
      expires_at: 10.minutes.from_now
    )

    assert_equal code_challenge, auth_code.code_challenge
    assert_equal code_challenge_method, auth_code.code_challenge_method
    assert auth_code.uses_pkce?
  end

  test "authorization code works without PKCE (backward compatibility)" do
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    assert_nil auth_code.code_challenge
    assert_nil auth_code.code_challenge_method
    assert_not auth_code.uses_pkce?
  end

  test "code_challenge_method validation accepts valid methods" do
    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    assert auth_code.valid?
  end

  test "code_challenge_method validation rejects invalid methods" do
    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      code_challenge_method: "invalid_method",
      expires_at: 10.minutes.from_now
    )

    assert_not auth_code.valid?
    assert_includes auth_code.errors[:code_challenge_method], "is not included in the list"
  end

  test "code_challenge format validation accepts valid base64url" do
    # Valid base64url encoded string (43 characters, valid characters)
    valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: valid_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    assert auth_code.valid?
  end

  test "code_challenge format validation rejects invalid format" do
    # Invalid: contains + character (not base64url)
    invalid_challenge = "dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk"

    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: invalid_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    assert_not auth_code.valid?
    assert_includes auth_code.errors[:code_challenge], "must be 43-128 characters of base64url encoding"
  end

  test "code_challenge format validation rejects wrong length" do
    # Invalid: too short (42 characters)
    short_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"

    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      code_challenge: short_challenge,
      code_challenge_method: "S256",
      expires_at: 10.minutes.from_now
    )

    assert_not auth_code.valid?
    assert_includes auth_code.errors[:code_challenge], "must be 43-128 characters of base64url encoding"
  end

  test "code_challenge validation is skipped when no challenge present" do
    auth_code = OidcAuthorizationCode.new(
      application: @application,
      user: @user,
      redirect_uri: "http://localhost:4000/callback",
      scope: "openid profile",
      expires_at: 10.minutes.from_now
    )

    # Should be valid even without code_challenge
    assert auth_code.valid?
  end
end