require "test_helper"

class OidcDeviceFlowControllerTest < ActionDispatch::IntegrationTest
  DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code".freeze

  def setup
    @group = Group.create!(name: "device-flow-testers", description: "test")
    @user = User.create!(email_address: "device_flow@example.com", password: "password123")
    @user.groups << @group

    @cli = Application.create!(
      name: "Device Flow CLI",
      slug: "device-flow-cli",
      app_type: "oidc",
      is_public_client: true,
      active: true
    )
    @cli.allowed_groups << @group

    @resource_secret = "resource-server-secret-value-1234567890"
    @resource = Application.create!(
      name: "Device Flow Resource Server",
      slug: "device-flow-rs",
      app_type: "oidc",
      client_secret: @resource_secret,
      active: true
    )
  end

  def teardown
    Current.session = nil
    [@cli, @resource].each do |app|
      OidcRefreshToken.where(application: app).delete_all
      OidcAccessToken.where(application: app).delete_all
      OidcDeviceCode.where(application: app).delete_all
      OidcUserConsent.where(application: app).delete_all
    end
  end

  # --- Discovery -------------------------------------------------------------

  test "discovery advertises the device grant and new endpoints" do
    get "/.well-known/openid-configuration"
    assert_response :success
    config = JSON.parse(@response.body)

    assert_includes config["grant_types_supported"], DEVICE_GRANT
    assert config["device_authorization_endpoint"].end_with?("/oauth/device_authorization")
    assert config["introspection_endpoint"].end_with?("/oauth/introspect")
  end

  # --- Device authorization endpoint -----------------------------------------

  test "device_authorization issues a device_code and user_code" do
    post "/oauth/device_authorization", params: {client_id: @cli.client_id, scope: "openid groups"}
    assert_response :success
    body = JSON.parse(@response.body)

    assert body["device_code"].present?
    assert_match(/\A[A-HJ-NP-Z2-9]{8}\z/, body["user_code"])
    assert body["verification_uri"].end_with?("/device")
    assert body["verification_uri_complete"].include?("user_code=#{body["user_code"]}")
    assert_equal 5, body["interval"]
    assert body["expires_in"].positive?
  end

  test "device_authorization rejects an unknown client" do
    post "/oauth/device_authorization", params: {client_id: "does-not-exist"}
    assert_response :unauthorized
    assert_equal "invalid_client", JSON.parse(@response.body)["error"]
  end

  # --- Token endpoint device_code grant --------------------------------------

  test "token endpoint returns authorization_pending while pending" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    poll(dc)
    assert_response :bad_request
    assert_equal "authorization_pending", JSON.parse(@response.body)["error"]
  end

  test "token endpoint returns slow_down when polled faster than the interval" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    poll(dc) # first poll records last_polled_at
    poll(dc) # immediate second poll is too fast
    assert_response :bad_request
    assert_equal "slow_down", JSON.parse(@response.body)["error"]
  end

  test "token endpoint returns expired_token for an expired code" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid", expires_at: 1.minute.ago)
    poll(dc)
    assert_response :bad_request
    assert_equal "expired_token", JSON.parse(@response.body)["error"]
  end

  test "token endpoint returns access_denied when the user denied" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    dc.deny!
    poll(dc)
    assert_response :bad_request
    assert_equal "access_denied", JSON.parse(@response.body)["error"]
  end

  test "token endpoint issues tokens once approved, then the code is single-use" do
    OidcUserConsent.create!(user: @user, application: @cli, scopes_granted: "openid groups", granted_at: Time.current)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid groups")
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)

    poll(dc)
    assert_response :success
    body = JSON.parse(@response.body)
    assert body["access_token"].present?
    assert body["refresh_token"].present?
    assert body["id_token"].present?
    assert_equal "Bearer", body["token_type"]
    assert_equal "openid groups", body["scope"]

    # Replaying the (now consumed) device_code fails.
    poll(dc)
    assert_response :bad_request
    assert_equal "invalid_grant", JSON.parse(@response.body)["error"]
  end

  # --- Verification page -----------------------------------------------------

  test "verification page shows the approval prompt for a signed-in allowed user" do
    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid groups")

    get "/device", params: {user_code: dc.user_code}
    assert_response :success
    assert_match(/Approve/, @response.body)
    assert_match(dc.user_code, @response.body)
  end

  test "approving records consent and approves the device code" do
    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid groups")

    post "/device", params: {user_code: dc.user_code}
    assert_response :success
    assert_match(/approved/i, @response.body)

    dc.reload
    assert dc.approved?
    assert_equal @user, dc.user
    assert OidcUserConsent.exists?(user: @user, application: @cli)
  end

  test "denying marks the device code denied" do
    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")

    post "/device", params: {user_code: dc.user_code, deny: "1"}
    assert_response :success
    dc.reload
    assert dc.denied?
  end

  test "a user without access cannot approve" do
    outsider = User.create!(email_address: "outsider@example.com", password: "password123")
    sign_in_as(outsider)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")

    post "/device", params: {user_code: dc.user_code}
    assert_response :success
    assert_match(/not allowed/i, @response.body)
    dc.reload
    assert dc.pending?, "device code must stay pending when approval is refused"
  end

  test "verification page requires authentication" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    get "/device", params: {user_code: dc.user_code}
    assert_redirected_to signin_path
  end

  # --- Introspection ---------------------------------------------------------

  test "introspection reports an active token with groups" do
    token = OidcAccessToken.create!(application: @cli, user: @user, scope: "openid groups")

    post "/oauth/introspect", params: {
      token: token.plaintext_token,
      client_id: @resource.client_id,
      client_secret: @resource_secret
    }
    assert_response :success
    body = JSON.parse(@response.body)

    assert_equal true, body["active"]
    assert_equal @cli.client_id, body["client_id"]
    assert_includes body["groups"], @group.name
    assert body["sub"].present?
  end

  test "introspection reports inactive for a revoked token" do
    token = OidcAccessToken.create!(application: @cli, user: @user, scope: "openid")
    token.revoke!

    post "/oauth/introspect", params: {
      token: token.plaintext_token,
      client_id: @resource.client_id,
      client_secret: @resource_secret
    }
    assert_response :success
    assert_equal false, JSON.parse(@response.body)["active"]
  end

  test "introspection requires valid caller credentials" do
    token = OidcAccessToken.create!(application: @cli, user: @user, scope: "openid")

    post "/oauth/introspect", params: {
      token: token.plaintext_token,
      client_id: @resource.client_id,
      client_secret: "wrong-secret"
    }
    assert_response :unauthorized
  end

  private

  def poll(device_code)
    post "/oauth/token", params: {
      grant_type: DEVICE_GRANT,
      device_code: device_code.plaintext_device_code,
      client_id: @cli.client_id
    }
  end
end
