require "test_helper"

# RFC 8707 Resource Indicators: a client names the target resource server via the
# `resource` parameter; clinch binds it to the token as `aud` and reports it at
# introspection. Validation is syntax-only (pass-through) — the resource server
# enforces the audience.
class OidcResourceIndicatorsTest < ActionDispatch::IntegrationTest
  DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code".freeze
  RESOURCE = "https://c2a2.example.com".freeze
  # RFC 7636 Appendix B example PKCE pair.
  PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".freeze
  PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".freeze

  def setup
    @group = Group.create!(name: "resource-testers", description: "test")
    @user = User.create!(email_address: "resource_test@example.com", password: "password123")
    @user.groups << @group

    @cli = Application.create!(name: "Resource CLI", slug: "resource-cli", app_type: "oidc", is_public_client: true, active: true)
    @cli.allowed_groups << @group

    @web = Application.create!(name: "Resource Web", slug: "resource-web", app_type: "oidc",
      is_public_client: true, active: true, skip_consent: true, redirect_uris: ["https://app.example.com/cb"].to_json)
    @web.allowed_groups << @group

    @resource_secret = "resource-server-secret-value-abcdefghij"
    @resource = Application.create!(name: "Resource RS", slug: "resource-rs2", app_type: "oidc",
      client_secret: @resource_secret, active: true)
  end

  def teardown
    Current.session = nil
    [@cli, @web, @resource].each do |app|
      OidcRefreshToken.where(application: app).delete_all
      OidcAccessToken.where(application: app).delete_all
      OidcDeviceCode.where(application: app).delete_all
      OidcAuthorizationCode.where(application: app).delete_all
      OidcUserConsent.where(application: app).delete_all
    end
  end

  # --- Authorization code flow ----------------------------------------------

  test "authorize binds the resource so introspection reports it as aud" do
    sign_in_as(@user)
    get "/oauth/authorize", params: {
      response_type: "code", client_id: @web.client_id,
      redirect_uri: "https://app.example.com/cb", scope: "openid",
      code_challenge: PKCE_CHALLENGE, code_challenge_method: "S256",
      resource: RESOURCE
    }
    assert_response :redirect
    code = Rack::Utils.parse_query(URI(@response.location).query)["code"]
    assert code.present?

    post "/oauth/token", params: {
      grant_type: "authorization_code", code: code,
      redirect_uri: "https://app.example.com/cb",
      client_id: @web.client_id, code_verifier: PKCE_VERIFIER
    }
    assert_response :success
    tokens = JSON.parse(@response.body)

    assert_equal RESOURCE, introspect(tokens["access_token"])["aud"]

    # The bound audience survives refresh rotation.
    post "/oauth/token", params: {grant_type: "refresh_token", refresh_token: tokens["refresh_token"], client_id: @web.client_id}
    assert_response :success
    rotated = JSON.parse(@response.body)
    assert_equal RESOURCE, introspect(rotated["access_token"])["aud"]
  end

  test "authorize rejects an invalid resource with invalid_target" do
    sign_in_as(@user)
    get "/oauth/authorize", params: {
      response_type: "code", client_id: @web.client_id,
      redirect_uri: "https://app.example.com/cb", scope: "openid",
      resource: "https://c2a2.example.com/path#frag"
    }
    assert_response :redirect
    assert_includes @response.location, "error=invalid_target"
  end

  # --- Device flow -----------------------------------------------------------

  test "device flow binds the resource to the issued token" do
    post "/oauth/device_authorization", params: {client_id: @cli.client_id, scope: "openid", resource: RESOURCE}
    assert_response :success
    auth = JSON.parse(@response.body)

    dc = OidcDeviceCode.find_by_user_code(auth["user_code"])
    assert_equal RESOURCE, dc.resource

    OidcUserConsent.create!(user: @user, application: @cli, scopes_granted: "openid", granted_at: Time.current)
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)

    post "/oauth/token", params: {grant_type: DEVICE_GRANT, device_code: auth["device_code"], client_id: @cli.client_id}
    assert_response :success
    access = JSON.parse(@response.body)["access_token"]

    assert_equal RESOURCE, introspect(access)["aud"]
  end

  test "device_authorization rejects an invalid resource" do
    post "/oauth/device_authorization", params: {client_id: @cli.client_id, resource: "not-an-absolute-uri"}
    assert_response :bad_request
    assert_equal "invalid_target", JSON.parse(@response.body)["error"]
  end

  # --- Fallback --------------------------------------------------------------

  test "introspection aud falls back to the client when no resource was bound" do
    token = OidcAccessToken.create!(application: @cli, user: @user, scope: "openid")
    assert_equal @cli.client_id, introspect(token.plaintext_token)["aud"]
  end

  private

  def introspect(token)
    post "/oauth/introspect", params: {token: token, client_id: @resource.client_id, client_secret: @resource_secret}
    JSON.parse(@response.body)
  end
end
