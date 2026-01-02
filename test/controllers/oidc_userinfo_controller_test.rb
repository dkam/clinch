require "test_helper"

class OidcUserinfoControllerTest < ActionDispatch::IntegrationTest
  def setup
    @user = users(:alice)
    @application = applications(:kavita_app)

    # Add user to a group for groups claim testing
    @admin_group = groups(:admin_group)
    @user.groups << @admin_group unless @user.groups.include?(@admin_group)
  end

  def teardown
    # Clean up
    OidcAccessToken.where(user: @user, application: @application).destroy_all
  end

  # ============================================================================
  # HTTP Method Tests (GET and POST)
  # ============================================================================

  test "userinfo endpoint accepts GET requests" do
    access_token = create_access_token("openid email profile")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert json["sub"].present?
  end

  test "userinfo endpoint accepts POST requests" do
    access_token = create_access_token("openid email profile")

    post "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert json["sub"].present?
  end

  test "userinfo endpoint accepts POST with access_token in body" do
    access_token = create_access_token("openid email profile")

    post "/oauth/userinfo", params: {
      access_token: access_token.plaintext_token
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert json["sub"].present?
  end

  # ============================================================================
  # Scope-Based Claim Filtering Tests
  # ============================================================================

  test "userinfo with openid scope only returns minimal claims" do
    access_token = create_access_token("openid")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # Required claims
    assert json["sub"].present?, "Should include sub claim"

    # Scope-dependent claims should NOT be present
    assert_nil json["email"], "Should not include email without email scope"
    assert_nil json["email_verified"], "Should not include email_verified without email scope"
    assert_nil json["name"], "Should not include name without profile scope"
    assert_nil json["preferred_username"], "Should not include preferred_username without profile scope"
    assert_nil json["groups"], "Should not include groups without groups scope"
  end

  test "userinfo with email scope includes email claims" do
    access_token = create_access_token("openid email")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # Required claims
    assert json["sub"].present?

    # Email claims should be present
    assert_equal @user.email_address, json["email"], "Should include email with email scope"
    assert_equal true, json["email_verified"], "Should include email_verified with email scope"

    # Profile claims should NOT be present
    assert_nil json["name"], "Should not include name without profile scope"
    assert_nil json["preferred_username"], "Should not include preferred_username without profile scope"
  end

  test "userinfo with profile scope includes profile claims" do
    access_token = create_access_token("openid profile")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # Required claims
    assert json["sub"].present?

    # All standard profile claims should be present (per OIDC Core spec section 5.4)
    # Some may be null if we don't have the data, but the keys should exist
    assert json.key?("name"), "Should include name claim"
    assert json.key?("given_name"), "Should include given_name claim (may be null)"
    assert json.key?("family_name"), "Should include family_name claim (may be null)"
    assert json.key?("middle_name"), "Should include middle_name claim (may be null)"
    assert json.key?("nickname"), "Should include nickname claim (may be null)"
    assert json.key?("preferred_username"), "Should include preferred_username claim"
    assert json.key?("profile"), "Should include profile claim (may be null)"
    assert json.key?("picture"), "Should include picture claim (may be null)"
    assert json.key?("website"), "Should include website claim (may be null)"
    assert json.key?("gender"), "Should include gender claim (may be null)"
    assert json.key?("birthdate"), "Should include birthdate claim (may be null)"
    assert json.key?("zoneinfo"), "Should include zoneinfo claim (may be null)"
    assert json.key?("locale"), "Should include locale claim (may be null)"
    assert json.key?("updated_at"), "Should include updated_at claim"

    # Verify preferred_username is using username or email
    assert json["preferred_username"].present?, "preferred_username should have a value"

    # Email claims should NOT be present
    assert_nil json["email"], "Should not include email without email scope"
    assert_nil json["email_verified"], "Should not include email_verified without email scope"
  end

  test "userinfo with groups scope includes groups claim" do
    access_token = create_access_token("openid groups")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # Required claims
    assert json["sub"].present?

    # Groups claim should be present
    assert json["groups"].present?, "Should include groups with groups scope"
    assert_includes json["groups"], "Administrators", "Should include user's groups"

    # Email and profile claims should NOT be present
    assert_nil json["email"], "Should not include email without email scope"
    assert_nil json["name"], "Should not include name without profile scope"
  end

  test "userinfo with multiple scopes includes all requested claims" do
    access_token = create_access_token("openid email profile groups")

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # All scope-based claims should be present
    assert json["sub"].present?
    assert json["email"].present?, "Should include email"
    assert json["email_verified"].present?, "Should include email_verified"
    assert json["name"].present?, "Should include name"
    assert json["preferred_username"].present?, "Should include preferred_username"
    assert json["groups"].present?, "Should include groups"
  end

  test "userinfo returns same filtered claims for GET and POST" do
    access_token = create_access_token("openid email")

    # GET request
    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }
    get_json = JSON.parse(response.body)

    # POST request
    post "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }
    post_json = JSON.parse(response.body)

    # Both should return the same claims
    assert_equal get_json, post_json, "GET and POST should return identical claims"
  end

  # ============================================================================
  # Authentication Tests
  # ============================================================================

  test "userinfo endpoint requires Bearer token" do
    get "/oauth/userinfo"

    assert_response :unauthorized
  end

  test "userinfo endpoint rejects invalid token" do
    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer invalid_token_12345"
    }

    assert_response :unauthorized
  end

  test "userinfo endpoint rejects expired token" do
    access_token = create_access_token("openid email profile")

    # Expire the token
    access_token.update!(expires_at: 1.hour.ago)

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :unauthorized
  end

  test "userinfo endpoint rejects revoked token" do
    access_token = create_access_token("openid email profile")

    # Revoke the token
    access_token.revoke!

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :unauthorized
  end

  # ============================================================================
  # Pairwise Subject Identifier Test
  # ============================================================================

  test "userinfo returns pairwise SID when consent exists" do
    access_token = create_access_token("openid")

    # Find existing consent or create new one (ensure it has a SID)
    consent = OidcUserConsent.find_or_initialize_by(
      user: @user,
      application: @application
    )
    consent.scopes_granted ||= "openid"
    consent.save!

    # Reload to get the auto-generated SID
    consent.reload

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{access_token.plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal consent.sid, json["sub"], "Should use pairwise SID from consent"
    assert consent.sid.present?, "Consent should have a SID"
  end

  private

  def create_access_token(scope)
    OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: scope
    )
  end
end
