require "test_helper"

# CLN-05: the subject is the contract an IdP makes with a relying party — the
# same person must be the same `sub` to a given client for as long as the
# account exists. Revoking and re-granting consent must not mint a new one, and
# nothing may fall back to the numeric user id, which is the same for every
# client and so defeats pairwise identifiers.
class PairwiseSubjectStabilityTest < ActionDispatch::IntegrationTest
  setup do
    @alice = users(:alice)
    @app = applications(:kavita_app) # alice_consent fixture, sid alice-kavita-sid-12345
    @legacy_sub = oidc_user_consents(:alice_consent).sid
  end

  test "revoking one application's consent and granting it again keeps the subject" do
    sign_in_as(@alice)
    delete revoke_consent_active_sessions_path, params: {application_id: @app.id}
    assert_nil OidcUserConsent.find_by(user: @alice, application: @app)

    consent = OidcUserConsent.record!(user: @alice, application: @app, scopes: %w[openid email])

    assert_equal @legacy_sub, id_token_sub(consent)
    assert_equal @legacy_sub, userinfo_sub
  end

  test "revoking every consent and granting again keeps the subject" do
    sign_in_as(@alice)
    delete revoke_all_consents_active_sessions_path
    consent = OidcUserConsent.record!(user: @alice, application: @app, scopes: %w[openid email])

    assert_equal @legacy_sub, id_token_sub(consent)
  end

  test "revoking every consent also revokes that user's tokens" do
    access = OidcAccessToken.create!(application: @app, user: @alice, scope: "openid email")
    refresh = OidcRefreshToken.create!(application: @app, user: @alice, oidc_access_token: access, scope: "openid email")
    sign_in_as(@alice)

    delete revoke_all_consents_active_sessions_path

    assert access.reload.revoked?, "access token must not outlive the consent"
    assert refresh.reload.revoked?, "refresh token must not outlive the consent"
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{access.plaintext_token}"}
    assert_response :unauthorized
  end

  test "a new user and client get a subject that is stable and is not the user id" do
    bob = users(:bob)
    OidcUserConsent.record!(user: bob, application: @app, scopes: %w[openid])
    token = OidcAccessToken.create!(application: @app, user: bob, scope: "openid")

    first = userinfo_sub(token)
    second = userinfo_sub(token)

    refute_equal bob.id.to_s, first
    assert_equal first, second
  end

  test "introspection reports the same subject as userinfo" do
    bob = users(:bob)
    OidcUserConsent.record!(user: bob, application: @app, scopes: %w[openid])
    token = OidcAccessToken.create!(application: @app, user: bob, scope: "openid")
    secret = @app.generate_new_client_secret!

    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: @app.client_id, client_secret: secret}
    introspected = JSON.parse(response.body)["sub"]

    refute_equal bob.id.to_s, introspected
    assert_equal userinfo_sub(token), introspected
  end

  test "the backchannel logout token names the stable subject, not the current consent's sid" do
    sign_in_as(@alice)
    delete revoke_consent_active_sessions_path, params: {application_id: @app.id}
    consent = OidcUserConsent.record!(user: @alice, application: @app, scopes: %w[openid])
    refute_equal @legacy_sub, consent.sid

    logout = JWT.decode(OidcJwtService.generate_logout_token(@alice, @app, consent), nil, false).first

    assert_equal @legacy_sub, logout["sub"]
    assert_equal consent.sid, logout["sid"]
  end

  # A token is only as good as the grant behind it. Destroying a consent revokes
  # its tokens, but the check at use time does not depend on every path having
  # done so — the same defence in depth CLN-01 applies to disabled users.
  test "a token whose consent is gone is refused at userinfo and reported inactive at introspection" do
    bob = users(:bob) # no consent for kavita
    token = OidcAccessToken.create!(application: @app, user: bob, scope: "openid email")

    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :unauthorized

    secret = @app.generate_new_client_secret!
    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: @app.client_id, client_secret: secret}
    assert_equal({"active" => false}, JSON.parse(response.body))
  end

  private

  def id_token_sub(consent)
    token = OidcJwtService.generate_id_token(@alice, @app, consent: consent, scopes: "openid email")
    JWT.decode(token, nil, false).first["sub"]
  end

  def userinfo_sub(token = OidcAccessToken.create!(application: @app, user: @alice, scope: "openid"))
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :success
    JSON.parse(response.body)["sub"]
  end
end
