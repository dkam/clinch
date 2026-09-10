require "test_helper"

# Regression tests for the remaining September 2026 review items fixed in the
# first batch: CLN-12, CLN-13, CLN-14, CLN-17, CLN-19.
class SecurityReviewPhase1Test < ActionDispatch::IntegrationTest
  # --- CLN-12 · revocation endpoint must check token ownership ---------------

  test "CLN-12 a client cannot revoke a token issued to a different client" do
    alice = users(:alice)
    owner = applications(:kavita_app)
    caller_app = applications(:another_app)
    caller_secret = caller_app.generate_new_client_secret!

    token = OidcAccessToken.create!(application: owner, user: alice, scope: "openid")

    post "/oauth/revoke", params: {
      token: token.plaintext_token,
      client_id: caller_app.client_id,
      client_secret: caller_secret
    }

    # RFC 7009 §2.2: still 200, disclosing nothing about the token.
    assert_response :ok
    refute token.reload.revoked?, "a client must not revoke another client's token"
  end

  test "CLN-12 a client can still revoke its own token" do
    alice = users(:alice)
    app = applications(:kavita_app)
    secret = app.generate_new_client_secret!
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid")

    post "/oauth/revoke", params: {
      token: token.plaintext_token,
      client_id: app.client_id,
      client_secret: secret
    }

    assert_response :ok
    assert token.reload.revoked?
  end

  test "CLN-12 a public client can revoke its own token with client_id alone" do
    alice = users(:alice)
    app = Application.create!(name: "Public Revoke App", slug: "public-revoke-app",
      app_type: "oidc", active: true, is_public_client: true,
      redirect_uris: ["https://public.example.com/cb"].to_json)
    assert app.public_client?, "guard precondition: app must have no secret"

    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid")

    post "/oauth/revoke", params: {token: token.plaintext_token, client_id: app.client_id}

    assert_response :ok
    assert token.reload.revoked?, "RFC 7009 permits a public client to revoke its own token"
  end

  # --- CLN-14 · bearer token must not be accepted in the query string --------

  test "CLN-14 userinfo refuses an access token passed as a query parameter" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")

    get "/oauth/userinfo", params: {access_token: token.plaintext_token}
    assert_response :unauthorized

    # The header form still works.
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :success
  end

  test "CLN-14 userinfo still accepts an access token in a form-encoded POST body" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")

    post "/oauth/userinfo", params: {access_token: token.plaintext_token},
      headers: {"Content-Type" => "application/x-www-form-urlencoded"}
    assert_response :success
  end

  # --- CLN-19 · WebAuthn errors must not echo library exception text ---------

  test "CLN-19 webauthn verification failure does not leak the exception message" do
    alice = users(:alice)

    # NOTE: WebAuthn::Credential#id returns the base64url *string*, and the app
    # stores Base64.urlsafe_encode64 of that, so external_id is double-encoded.
    # Mirror that here so the credential lookup in webauthn_verify succeeds and
    # the request reaches the verification step.
    credential_id = Base64.urlsafe_encode64("credcln19abc")
    alice.webauthn_credentials.create!(external_id: Base64.urlsafe_encode64(credential_id),
      public_key: Base64.urlsafe_encode64(Base64.urlsafe_encode64("fake-public-key")), nickname: "test key", sign_count: 0)

    post "/sessions/webauthn/challenge", params: {email: alice.email_address}
    assert_response :success

    # A well-formed assertion carrying the wrong challenge and origin, so the
    # library's own verification raises WebAuthn::Error — the branch that used
    # to interpolate e.message straight into the JSON response.
    client_data = {
      type: "webauthn.get",
      challenge: Base64.urlsafe_encode64("not-the-issued-challenge"),
      origin: "https://attacker.example.com"
    }.to_json

    post "/sessions/webauthn/verify", params: {
      credential: {
        id: credential_id,
        rawId: credential_id,
        type: "public-key",
        response: {
          clientDataJSON: Base64.urlsafe_encode64(client_data),
          authenticatorData: Base64.urlsafe_encode64("\x00" * 37),
          signature: Base64.urlsafe_encode64("sig")
        }
      }
    }, as: :json

    refute_equal 200, response.status
    error = JSON.parse(response.body)["error"].to_s
    refute_equal "Credential not found", error, "guard: the test must reach the verification step"
    refute_match(/Authentication failed:/, error, "must not interpolate the exception message")
    refute_match(/origin|rp_id|rp id|challenge|counter|attacker/i, error,
      "must not leak ceremony detail: #{error}")
  end

  # --- CLN-17 · forward-auth bearer path must require a forwarded host -------

  test "CLN-17 bearer path fails closed when no forwarded host is present" do
    user = User.create!(email_address: "cln17@example.com", password: "password123")
    group = Group.create!(name: "cln17-group", description: "test")
    user.groups << group
    app = Application.create!(name: "CLN17 App", slug: "cln17-app", app_type: "forward_auth",
      domain_pattern: "cln17.example.com", active: true)
    app.allowed_groups << group
    key = ApiKey.create!(user: user, application: app, name: "cln17 key")

    # No X-Forwarded-Host and no Host: a proxy misconfiguration that drops the
    # header must not yield identity headers, exactly as the cookie path already
    # refuses. Integration requests always send a Host, so blank it explicitly.
    get "/api/verify", headers: {"Authorization" => "Bearer #{key.plaintext_token}", "Host" => ""}

    refute_equal 200, response.status, "must not authorise without a forwarded host"
    assert_nil response.headers["x-remote-user"], "no identity headers without a resolved host"
  end
end
