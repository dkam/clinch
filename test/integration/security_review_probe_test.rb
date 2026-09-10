require "test_helper"
require "clinch/internal_host_patterns"

# Regression tests for the September 2026 security review
# (docs/security-review-2026-09.md).
#
# These began as probes asserting the *insecure* behaviour. As each finding is
# fixed its assertions are inverted, so a test here asserts the secure behaviour
# once its finding is closed.
#
# STILL ASSERTING THE BUG (not yet fixed): CLN-05, CLN-06. Invert those when
# their findings are addressed.
class ReviewProbeTest < ActionDispatch::IntegrationTest
  test "CLN-08 consent page CSP carries form-action limited to self and the redirect host" do
    bob = users(:bob)
    app = applications(:kavita_app)
    sign_in_as(bob)
    get "/oauth/authorize", params: {
      client_id: app.client_id, redirect_uri: "https://kavita.example.com/signin-oidc",
      response_type: "code", scope: "openid"
    }
    assert_response :success
    assert_match(/requesting access/, response.body)
    csp = response.headers["Content-Security-Policy"].to_s
    assert_match(/form-action/, csp, "form-action must be present on the consent page: #{csp}")
    assert_match(%r{form-action[^;]*'self'}, csp, "form-action must still allow 'self': #{csp}")
    assert_match(%r{form-action[^;]*https://kavita\.example\.com}, csp, "form-action must allow the client redirect host: #{csp}")
  end

  test "CLN-01 disabled user's access token is refused at userinfo and introspect" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")
    alice.update!(status: :disabled)
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :unauthorized

    secret = app.generate_new_client_secret!
    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: app.client_id, client_secret: secret}
    assert_equal false, JSON.parse(response.body)["active"]
  end

  test "CLN-01 deactivating a user revokes their tokens, API keys, and pending grants" do
    alice = users(:alice)
    app = applications(:kavita_app)
    access = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")
    refresh = OidcRefreshToken.create!(application: app, user: alice, oidc_access_token: access, scope: "openid")

    alice.update!(status: :disabled)

    assert access.reload.revoked?, "access token should be revoked on deactivation"
    assert refresh.reload.revoked?, "refresh token should be revoked on deactivation"
    assert_equal 0, alice.api_keys.active.count, "API keys should be revoked on deactivation"
  end

  # NOT YET FIXED — asserts the current (insecure) behaviour.
  test "CLN-05 revoke_all_consents leaves tokens valid and sub falls back to numeric user id" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")
    sign_in_as(alice)
    delete "/active_sessions/revoke_all_consents"
    assert_redirected_to "/active_sessions"
    assert_equal 0, alice.oidc_user_consents.count
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :success
    assert_equal alice.id.to_s, JSON.parse(response.body)["sub"]
  end

  # NOT YET FIXED — asserts the current (insecure) behaviour.
  test "CLN-06 GET /logout with no id_token_hint destroys the session" do
    alice = users(:alice)
    sign_in_as(alice)
    sid = Session.last.id
    get "/logout"
    assert_redirected_to "/"
    assert_nil Session.find_by(id: sid)
  end

  test "CLN-11 profile password change revokes other sessions but keeps the current one" do
    alice = users(:alice)
    other = alice.sessions.create!(user_agent: "other device")
    sign_in_as(alice)
    current = Current.session
    patch "/profile", params: {user: {current_password: "password", password: "newpassword123", password_confirmation: "newpassword123"}}
    assert_redirected_to "/profile"
    refute Session.exists?(other.id), "other session should have been revoked"
    assert Session.exists?(current.id), "the session doing the change should survive"
  end

  # Full coverage lives in test/lib/internal_host_patterns_test.rb; this keeps the
  # finding's own assertion inverted alongside the others.
  test "CLN-09 internal-IP host patterns are anchored" do
    patterns = Clinch::InternalHostPatterns.all
    refute patterns.any? { |p| p.match?("192.168.1.1.evil.com") }
    refute patterns.any? { |p| p.match?("evil.com.10.0.0.1") }
    assert patterns.any? { |p| p.match?("192.168.1.1") }
  end

  test "CLN-04 refresh grant with no consent mints nothing and leaves the token usable" do
    alice = users(:alice)
    app = applications(:another_app) # alice has no consent here
    secret = app.generate_new_client_secret!
    at = OidcAccessToken.create!(application: app, user: alice, scope: "openid")
    rt = OidcRefreshToken.create!(application: app, user: alice, oidc_access_token: at, scope: "openid")
    grant_everyone_access(app)
    before = OidcAccessToken.where(application: app, user: alice).count
    post "/oauth/token", params: {grant_type: "refresh_token", refresh_token: rt.token, client_id: app.client_id, client_secret: secret}
    assert_response :bad_request
    assert_equal "invalid_grant", JSON.parse(response.body)["error"]
    assert_equal before, OidcAccessToken.where(application: app, user: alice).count, "no access token should be minted when consent is missing"
    refute rt.reload.revoked?, "the presented refresh token should not be revoked when the grant is refused"
  end
end
