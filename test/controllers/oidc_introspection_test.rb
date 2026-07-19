require "test_helper"

# RFC 7662 token introspection: authorization (who may introspect which token)
# and claim scope-gating (only disclose identity claims the token was granted).
class OidcIntrospectionTest < ActionDispatch::IntegrationTest
  RESOURCE = "https://api.example.com".freeze

  def setup
    @group = Group.create!(name: "introspection-testers", description: "test")
    @user = User.create!(email_address: "introspect@example.com", password: "password123")
    @user.groups << @group

    # The OAuth client the tokens are issued to (a public CLI-style client).
    @client = Application.create!(name: "Introspect Client", slug: "introspect-client",
      app_type: "oidc", is_public_client: true, active: true)

    # The resource server that serves RESOURCE and is allowed to introspect
    # tokens bound to it.
    @rs_secret = "rs-secret-value-abcdefghijklmnop"
    @rs = Application.create!(name: "Introspect RS", slug: "introspect-rs", app_type: "oidc",
      client_secret: @rs_secret, active: true, resource_identifiers: [RESOURCE].to_json)

    # A confidential client that neither issued the token nor serves its resource.
    @other_secret = "other-secret-value-abcdefghijklmn"
    @other = Application.create!(name: "Introspect Other", slug: "introspect-other",
      app_type: "oidc", client_secret: @other_secret, active: true)
  end

  def teardown
    [@client, @rs, @other].each do |app|
      OidcAccessToken.where(application: app).delete_all
      OidcUserConsent.where(application: app).delete_all
    end
  end

  # --- Authorization ---------------------------------------------------------

  test "a resource server may introspect a token bound to a resource it serves" do
    token = issue(scope: "openid groups email", resource: RESOURCE)
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_equal true, body["active"]
    assert_equal @client.client_id, body["client_id"]
    assert_equal RESOURCE, body["aud"]
  end

  test "a client may introspect its own token" do
    token = OidcAccessToken.create!(application: @rs, user: @user, scope: "openid")
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_equal true, body["active"]
    assert_equal @rs.client_id, body["aud"]
  end

  test "a caller cannot introspect a token bound to a resource it does not serve" do
    token = issue(scope: "openid groups email", resource: RESOURCE)
    body = introspect(token, @other.client_id, @other_secret)

    assert_equal false, body["active"], "unauthorized caller must learn nothing"
    assert_nil body["username"]
    assert_nil body["groups"]
  end

  test "a caller cannot introspect an unbound token it did not issue" do
    token = issue(scope: "openid groups", resource: nil)
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_equal false, body["active"]
  end

  # --- Claim scope-gating ----------------------------------------------------

  test "omits email and groups when the token lacks those scopes" do
    token = issue(scope: "openid", resource: RESOURCE)
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_equal true, body["active"]
    assert_not body.key?("username"), "email must not leak without the email scope"
    assert_not body.key?("groups"), "groups must not leak without the groups scope"
  end

  test "includes email only with the email scope" do
    token = issue(scope: "openid email", resource: RESOURCE)
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_equal @user.email_address, body["username"]
    assert_not body.key?("groups")
  end

  test "includes groups only with the groups scope" do
    token = issue(scope: "openid groups", resource: RESOURCE)
    body = introspect(token, @rs.client_id, @rs_secret)

    assert_includes body["groups"], @group.name
    assert_not body.key?("username")
  end

  # --- Token / caller validity ----------------------------------------------

  test "reports inactive for a revoked token even to an authorized caller" do
    token = issue(scope: "openid groups", resource: RESOURCE)
    token.revoke!
    assert_equal false, introspect(token, @rs.client_id, @rs_secret)["active"]
  end

  test "requires valid caller credentials" do
    token = issue(scope: "openid", resource: RESOURCE)
    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: @rs.client_id, client_secret: "wrong"}
    assert_response :unauthorized
  end

  test "rejects a public (non-confidential) caller" do
    token = issue(scope: "openid", resource: RESOURCE)
    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: @client.client_id}
    assert_response :unauthorized
  end

  test "requires a token parameter" do
    post "/oauth/introspect", params: {client_id: @rs.client_id, client_secret: @rs_secret}
    assert_response :bad_request
    assert_equal "invalid_request", JSON.parse(@response.body)["error"]
  end

  private

  def issue(scope:, resource:)
    OidcAccessToken.create!(application: @client, user: @user, scope: scope, resource: resource)
  end

  def introspect(token, client_id, secret)
    plaintext = token.respond_to?(:plaintext_token) ? token.plaintext_token : token
    post "/oauth/introspect", params: {token: plaintext, client_id: client_id, client_secret: secret}
    assert_response :success
    JSON.parse(@response.body)
  end
end
