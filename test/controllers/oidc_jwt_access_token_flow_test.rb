require "test_helper"

# End-to-end: a client with access_token_format "jwt" gets an RFC 9068 token
# from the token endpoint, can verify it offline against the JWKS, and can still
# introspect and revoke it. ADR 0007.
class OidcJwtAccessTokenFlowTest < ActionDispatch::IntegrationTest
  RESOURCE = "https://shopo.example.com".freeze
  PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".freeze
  PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".freeze

  def setup
    @group = Group.create!(name: "jwt-testers", description: "test")
    @user = User.create!(email_address: "jwt_flow@example.com", password: "password123")
    @user.groups << @group

    @web = Application.create!(name: "JWT Web", slug: "jwt-web", app_type: "oidc",
      is_public_client: true, active: true, skip_consent: true,
      access_token_format: "jwt",
      redirect_uris: ["https://app.example.com/cb"].to_json)
    @web.allowed_groups << @group
  end

  def teardown
    Current.session = nil
    OidcRefreshToken.where(application: @web).delete_all
    OidcAccessToken.where(application: @web).delete_all
    OidcAuthorizationCode.where(application: @web).delete_all
    OidcUserConsent.where(application: @web).delete_all
  end

  def exchange(scope: "openid email groups", resource: RESOURCE)
    sign_in_as(@user)
    params = {
      response_type: "code", client_id: @web.client_id,
      redirect_uri: "https://app.example.com/cb", scope: scope,
      code_challenge: PKCE_CHALLENGE, code_challenge_method: "S256"
    }
    params[:resource] = resource if resource
    get "/oauth/authorize", params: params
    assert_response :redirect
    code = Rack::Utils.parse_query(URI(@response.location).query)["code"]

    token_params = {
      grant_type: "authorization_code", code: code,
      redirect_uri: "https://app.example.com/cb",
      client_id: @web.client_id, code_verifier: PKCE_VERIFIER
    }
    token_params[:resource] = resource if resource
    post "/oauth/token", params: token_params
    assert_response :success
    JSON.parse(@response.body)
  end

  test "the token endpoint returns a verifiable RFC 9068 access token" do
    body = exchange
    access = body["access_token"]

    payload, header = JWT.decode(access, OidcJwtService.public_key, true, {algorithm: "RS256"})

    assert_equal "at+jwt", header["typ"]
    assert_equal RESOURCE, payload["aud"]
    assert_equal @web.client_id, payload["client_id"]
    assert_equal @user.email_address, payload["email"]
    assert_includes payload["groups"], "jwt-testers"
    assert_equal body["expires_in"], payload["exp"] - payload["iat"]
  end

  # A resource server that only has the JWKS must be able to verify the token
  # with no further calls to clinch — that is the entire point of the format.
  test "the published JWKS verifies the token without any clinch callback" do
    access = exchange["access_token"]

    get "/.well-known/jwks.json"
    assert_response :success
    jwk = JSON.parse(@response.body)["keys"].first

    key = JWT::JWK.import(jwk.slice("kty", "n", "e", "kid")).verify_key
    payload, header = JWT.decode(access, key, true, {algorithm: "RS256"})

    assert_equal jwk["kid"], header["kid"], "kid must let a client pick the right key on rotation"
    # sub is the pairwise sid from consent — the same subject introspection and
    # the ID token report, so a resource server can correlate them.
    assert_equal OidcUserConsent.find_by(user: @user, application: @web).sid, payload["sub"]
  end

  test "at_hash in the ID token covers the delivered JWT, not the internal handle" do
    body = exchange
    expected = Base64.urlsafe_encode64(
      Digest::SHA256.digest(body["access_token"])[0..15], padding: false
    )

    id_token = JWT.decode(body["id_token"], nil, false).first
    assert_equal expected, id_token["at_hash"],
      "OIDC Core §3.1.3.6 hashes the access token as delivered; a client validating at_hash would reject this login"
  end

  test "a JWT access token is still introspectable and revocable" do
    body = exchange
    access = body["access_token"]

    rs_secret = "introspection-caller-secret-abcdefghij"
    rs = Application.create!(name: "Shopo RS", slug: "shopo-rs", app_type: "oidc",
      client_secret: rs_secret, active: true, resource_identifiers: [RESOURCE].to_json)

    post "/oauth/introspect", params: {token: access},
      headers: {"HTTP_AUTHORIZATION" => ActionController::HttpAuthentication::Basic.encode_credentials(rs.client_id, rs_secret)}
    assert_response :success
    assert JSON.parse(@response.body)["active"], "a JWT presented to introspection must resolve to its record"

    post "/oauth/revoke", params: {token: access, client_id: @web.client_id}
    assert_response :success

    post "/oauth/introspect", params: {token: access},
      headers: {"HTTP_AUTHORIZATION" => ActionController::HttpAuthentication::Basic.encode_credentials(rs.client_id, rs_secret)}
    assert_not JSON.parse(@response.body)["active"], "revocation must still work for JWT clients"
  ensure
    rs&.destroy
  end

  test "userinfo accepts a JWT access token" do
    access = exchange["access_token"]

    get "/oauth/userinfo", headers: {"HTTP_AUTHORIZATION" => "Bearer #{access}"}
    assert_response :success
    assert_equal @user.email_address, JSON.parse(@response.body)["email"]
  end

  test "a refreshed token keeps the JWT format and the bound audience" do
    refresh = exchange["refresh_token"]

    post "/oauth/token", params: {
      grant_type: "refresh_token", refresh_token: refresh, client_id: @web.client_id
    }
    assert_response :success
    access = JSON.parse(@response.body)["access_token"]

    payload, header = JWT.decode(access, OidcJwtService.public_key, true, {algorithm: "RS256"})
    assert_equal "at+jwt", header["typ"], "refresh must not silently fall back to an opaque token"
    assert_equal RESOURCE, payload["aud"], "the audience must survive rotation"
  end

  test "an opaque client is entirely unaffected" do
    @web.update!(access_token_format: "opaque")
    access = exchange["access_token"]

    assert_not access.include?("."), "default clients must keep receiving opaque handles"
  end
end
