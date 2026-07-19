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
    post "/oauth/device_authorization", params: {
      client_id: @cli.client_id, scope: "openid groups",
      code_challenge: code_challenge_for(CODE_VERIFIER)
    }
    assert_response :success
    body = JSON.parse(@response.body)

    assert body["device_code"].present?
    assert_match(/\A[A-HJ-NP-Z2-9]{8}\z/, body["user_code"])
    assert body["verification_uri"].end_with?("/device")
    assert body["verification_uri_complete"].include?("user_code=#{body["user_code"]}")
    assert_equal 5, body["interval"]
    assert body["expires_in"].positive?
  end

  test "device_authorization requires PKCE for a public client" do
    post "/oauth/device_authorization", params: {client_id: @cli.client_id, scope: "openid"}
    assert_response :bad_request
    assert_equal "invalid_request", JSON.parse(@response.body)["error"]
    assert_equal 0, OidcDeviceCode.where(application: @cli).count
  end

  test "device_authorization rejects an unknown client" do
    post "/oauth/device_authorization", params: {client_id: "does-not-exist"}
    assert_response :unauthorized
    assert_equal "invalid_client", JSON.parse(@response.body)["error"]
  end

  test "device_authorization rejects a confidential client with no secret" do
    post "/oauth/device_authorization", params: {client_id: @resource.client_id, scope: "openid"}
    assert_response :unauthorized
    assert_equal "invalid_client", JSON.parse(@response.body)["error"]
  end

  test "device_authorization rejects a confidential client with a wrong secret" do
    post "/oauth/device_authorization",
      params: {client_id: @resource.client_id, client_secret: "wrong-secret", scope: "openid"}
    assert_response :unauthorized
    assert_equal "invalid_client", JSON.parse(@response.body)["error"]
  end

  test "device_authorization accepts a confidential client with a valid secret" do
    post "/oauth/device_authorization", params: {
      client_id: @resource.client_id, client_secret: @resource_secret, scope: "openid",
      code_challenge: code_challenge_for(CODE_VERIFIER), code_challenge_method: "S256"
    }
    assert_response :success
    assert JSON.parse(@response.body)["device_code"].present?
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

  test "slow_down interval is capped and does not grow without bound" do
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    # Hammer the code far more times than it would take to exceed the cap if the
    # interval grew by 5 unbounded (20 * 5 = 100s >> MAX_INTERVAL).
    20.times { poll(dc) }
    assert_operator dc.reload.interval, :<=, OidcDeviceCode::MAX_INTERVAL
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
    dc = OidcDeviceCode.create!(
      application: @cli, scope: "openid groups",
      code_challenge: code_challenge_for(CODE_VERIFIER), code_challenge_method: "S256"
    )
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)

    poll(dc, code_verifier: CODE_VERIFIER)
    assert_response :success
    body = JSON.parse(@response.body)
    assert body["access_token"].present?
    assert body["refresh_token"].present?
    assert body["id_token"].present?
    assert_equal "Bearer", body["token_type"]
    assert_equal "openid groups", body["scope"]

    # Replaying the (now consumed) device_code fails, and is reported as reuse —
    # distinguishable from the generic "Invalid device_code" for an unknown code.
    poll(dc, code_verifier: CODE_VERIFIER)
    assert_response :bad_request
    replay = JSON.parse(@response.body)
    assert_equal "invalid_grant", replay["error"]
    assert_match(/already been used/i, replay["error_description"])
  end

  test "replaying a redeemed device_code revokes the tokens it issued" do
    OidcUserConsent.create!(user: @user, application: @cli, scopes_granted: "openid", granted_at: Time.current)
    dc = OidcDeviceCode.create!(
      application: @cli, scope: "openid",
      code_challenge: code_challenge_for(CODE_VERIFIER), code_challenge_method: "S256"
    )
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)

    poll(dc, code_verifier: CODE_VERIFIER)
    assert_response :success
    access = OidcAccessToken.find_by_token(JSON.parse(@response.body)["access_token"])
    refresh = OidcRefreshToken.where(oidc_device_code: dc).first
    assert access.active?, "token should be live before the replay"

    # The code is kept (not destroyed) so the replay is detectable...
    assert dc.reload.redeemed?
    poll(dc, code_verifier: CODE_VERIFIER)
    assert_response :bad_request

    # ...and every token descended from the replayed code is revoked.
    assert access.reload.revoked?
    assert refresh.reload.revoked?
  end

  test "token endpoint refuses a PKCE-required client whose device_code lacks a challenge" do
    OidcUserConsent.create!(user: @user, application: @cli, scopes_granted: "openid", granted_at: Time.current)
    # A device_code minted without PKCE (e.g. slipped past the front door) must
    # never redeem tokens for a public client.
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    dc.approve!(user: @user, acr: "1", auth_time: Time.current.to_i)

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

  test "approving a narrower device request merges into existing consent" do
    # User already consented to a broader scope set (with stored claims) via the
    # browser flow.
    existing = OidcUserConsent.create!(
      user: @user, application: @cli,
      scopes_granted: "openid email profile groups",
      claims_requests: {"userinfo" => {"email" => nil}},
      granted_at: 1.day.ago
    )

    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    post "/device", params: {user_code: dc.user_code}
    assert_response :success

    existing.reload
    # Prior scopes are preserved (union), not shrunk to the device request's "openid".
    assert_equal %w[openid email profile groups].sort, existing.scopes.sort
    # Stored claims are not wiped.
    assert_equal({"userinfo" => {"email" => nil}}, existing.parsed_claims_requests)
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

  # --- Terminal-state rendering (shared resolver + partial) ------------------

  test "show prompts for a code when none is given" do
    sign_in_as(@user)
    get "/device"
    assert_response :success
    assert_match(/Enter device code/i, @response.body)
  end

  test "show renders the not-found terminal state for an unknown code" do
    sign_in_as(@user)
    get "/device", params: {user_code: "ZZZZ9999"}
    assert_response :success
    assert_match(/Code not found/i, @response.body)
  end

  test "show renders the expired terminal state" do
    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid", expires_at: 1.minute.ago)
    get "/device", params: {user_code: dc.user_code}
    assert_response :success
    assert_match(/Code expired/i, @response.body)
  end

  test "verify renders the terminal state for an already-handled code" do
    sign_in_as(@user)
    dc = OidcDeviceCode.create!(application: @cli, scope: "openid")
    dc.deny!
    post "/device", params: {user_code: dc.user_code}
    assert_response :success
    assert_match(/Code already used/i, @response.body)
  end

  # Introspection is covered in depth in oidc_introspection_test.rb.

  private

  # A valid PKCE verifier (48 chars, RFC 7636 charset) and its S256 challenge.
  CODE_VERIFIER = "device_flow_pkce_code_verifier_0123456789_abcdef".freeze

  def code_challenge_for(verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
  end

  def poll(device_code, code_verifier: nil)
    params = {
      grant_type: DEVICE_GRANT,
      device_code: device_code.plaintext_device_code,
      client_id: @cli.client_id
    }
    params[:code_verifier] = code_verifier if code_verifier
    post "/oauth/token", params: params
  end
end
