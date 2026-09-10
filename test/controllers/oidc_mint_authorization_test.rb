require "test_helper"

# Tokens must not be minted for a user who has lost access (deactivated, or removed
# from the application's allowed group) between authorization and the token request.
# Every grant re-checks Application#user_allowed? at mint time.
class OidcMintAuthorizationTest < ActionDispatch::IntegrationTest
  DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code".freeze

  def setup
    @group = Group.create!(name: "mint-authz-testers", description: "test")
    @user = User.create!(email_address: "mint_authz@example.com", password: "password123")
    @user.groups << @group

    @secret = "mint-authz-secret-value-abcdefghij"
    @application = Application.create!(name: "Mint Authz App", slug: "mint-authz-app", app_type: "oidc",
      client_secret: @secret, active: true, require_pkce: false,
      redirect_uris: ["https://app.example.com/cb"].to_json)
    @application.allowed_groups << @group

    OidcUserConsent.create!(user: @user, application: @application, scopes_granted: "openid", granted_at: Time.current)
  end

  def teardown
    OidcRefreshToken.where(application: @application).delete_all
    OidcAccessToken.where(application: @application).delete_all
    OidcDeviceCode.where(application: @application).delete_all
    OidcAuthorizationCode.where(application: @application).delete_all
    OidcUserConsent.where(application: @application).delete_all
  end

  # --- Device grant ----------------------------------------------------------

  test "device grant issues tokens for a still-allowed user" do
    poll(approved_device_code)
    assert_response :success
    assert JSON.parse(@response.body)["access_token"].present?
  end

  test "device grant refuses a user removed from the allowed group after approval" do
    dc = approved_device_code
    revoke_group!
    poll(dc)
    assert_access_denied
  end

  test "device grant refuses a deactivated user after approval" do
    dc = approved_device_code
    @user.disabled!
    poll(dc)
    assert_access_denied
  end

  # --- Authorization code grant ---------------------------------------------

  test "authorization_code grant refuses a user removed from the allowed group" do
    code = OidcAuthorizationCode.create!(application: @application, user: @user,
      redirect_uri: "https://app.example.com/cb", scope: "openid", auth_time: Time.current.to_i, acr: "1")
    revoke_group!
    post "/oauth/token", params: {grant_type: "authorization_code", code: code.plaintext_code,
      redirect_uri: "https://app.example.com/cb", client_id: @application.client_id, client_secret: @secret}
    assert_access_denied
  end

  # --- Refresh grant ---------------------------------------------------------

  # Deactivation now revokes the user's refresh tokens outright (see
  # User#revoke_sessions_when_deactivated), so the grant is refused as a revoked
  # token before the mint-time user_allowed? check is ever reached. That is the
  # stronger guarantee — the token is dead, not merely unusable at this client.
  # The group-removal test below still exercises the user_allowed? path.
  test "refresh_token grant refuses a deactivated user" do
    refresh = issue_refresh_token
    @user.disabled!

    assert refresh.reload.revoked?, "deactivation should revoke outstanding refresh tokens"

    refresh_with(refresh)
    assert_response :bad_request
    assert_equal "invalid_grant", JSON.parse(@response.body)["error"]
  end

  # Defence in depth: if a user is deactivated by a path that skips the model
  # callback, the mint-time user_allowed? check must still refuse the refresh.
  test "refresh_token grant refuses a deactivated user whose tokens were not revoked" do
    refresh = issue_refresh_token
    @user.update_column(:status, User.statuses[:disabled])

    assert_not refresh.reload.revoked?, "guard precondition: token still live"

    refresh_with(refresh)
    assert_access_denied
  end

  test "refresh_token grant refuses a removed user and leaves the token intact" do
    refresh = issue_refresh_token
    revoke_group!
    refresh_with(refresh)
    assert_access_denied
    assert_not refresh.reload.revoked?, "a denied refresh must not rotate/revoke the token"
  end

  private

  def approved_device_code
    dc = OidcDeviceCode.create!(application: @application, scope: "openid")
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)
    dc
  end

  def issue_refresh_token
    access = OidcAccessToken.create!(application: @application, user: @user, scope: "openid")
    OidcRefreshToken.create!(application: @application, user: @user, oidc_access_token: access,
      scope: "openid", auth_time: Time.current.to_i, acr: "1")
  end

  def revoke_group!
    UserGroup.where(user: @user, group: @group).delete_all
    @user.reload
  end

  def poll(dc)
    post "/oauth/token", params: {grant_type: DEVICE_GRANT, device_code: dc.plaintext_device_code,
      client_id: @application.client_id, client_secret: @secret}
  end

  def refresh_with(refresh)
    post "/oauth/token", params: {grant_type: "refresh_token", refresh_token: refresh.token,
      client_id: @application.client_id, client_secret: @secret}
  end

  def assert_access_denied
    assert_response :bad_request
    assert_equal "access_denied", JSON.parse(@response.body)["error"]
  end
end
