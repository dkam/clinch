require "test_helper"

# RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens.
#
# An application may opt into `access_token_format: "jwt"`, in which case the
# access token it receives is a signed JWT that a resource server verifies
# offline against clinch's JWKS instead of calling introspection on every
# request. See docs/decisions/0007-jwt-access-tokens.md.
class JwtAccessTokenTest < ActiveSupport::TestCase
  def setup
    @user = users(:alice)
    @application = applications(:kavita_app)
    @application.update!(access_token_format: "jwt")
  end

  def build_token(scope: "openid email groups", resource: "https://c2a2.example.com")
    OidcAccessToken.create!(
      application: @application, user: @user, scope: scope, resource: resource
    )
  end

  test "applications default to opaque access tokens" do
    assert_equal "opaque", applications(:another_app).access_token_format
    assert_not applications(:another_app).jwt_access_tokens?
  end

  test "access_token_format only accepts known values" do
    @application.access_token_format = "sometimes"
    assert_not @application.valid?
    assert_includes @application.errors[:access_token_format].join, "not a supported"
  end

  test "wire_value returns the opaque handle for an opaque application" do
    @application.update!(access_token_format: "opaque")
    record = build_token

    assert_equal record.plaintext_token, record.wire_value
    assert_not record.wire_value.include?("."), "opaque token must not look like a JWT"
  end

  test "wire_value returns a verifiable at+jwt for a jwt application" do
    record = build_token
    token = record.wire_value

    payload, header = JWT.decode(token, OidcJwtService.public_key, true, {algorithm: "RS256"})

    assert_equal "at+jwt", header["typ"], "RFC 9068 §2.1 requires typ=at+jwt"
    assert_equal "RS256", header["alg"]
    assert_equal OidcJwtService.send(:key_id), header["kid"], "must name the signing key so a client can rotate"
    assert_equal OidcJwtService.issuer_url, payload["iss"]
    assert_equal @user.id.to_s, payload["sub"]
    assert_equal "https://c2a2.example.com", payload["aud"], "audience is the RFC 8707 resource"
    assert_equal @application.client_id, payload["client_id"]
    assert_equal "openid email groups", payload["scope"]
    assert_equal record.expires_at.to_i, payload["exp"]
    assert_equal record.token_hmac, payload["jti"], "jti must resolve back to the stored token"
    assert_not_nil payload["iat"]
  end

  test "jwt audience falls back to client_id when no resource was requested" do
    record = build_token(resource: nil)
    payload = JWT.decode(record.wire_value, OidcJwtService.public_key, true, {algorithm: "RS256"}).first

    assert_equal @application.client_id, payload["aud"]
  end

  test "identity claims are scope-gated exactly as introspection gates them" do
    with_email = JWT.decode(build_token(scope: "openid email").wire_value, nil, false).first
    assert_equal @user.email_address, with_email["email"]
    assert_nil with_email["groups"], "groups must not leak without the groups scope"

    without = JWT.decode(build_token(scope: "openid").wire_value, nil, false).first
    assert_nil without["email"], "email must not leak without the email scope"
    assert_nil without["groups"]
  end

  test "a jwt access token still resolves to its record for introspection and revocation" do
    record = build_token
    found = OidcAccessToken.find_by_presented_token(record.wire_value)

    assert_equal record.id, found&.id, "a JWT must be introspectable and revocable like any token"
  end

  test "opaque tokens still resolve through the same lookup" do
    @application.update!(access_token_format: "opaque")
    record = build_token

    assert_equal record.id, OidcAccessToken.find_by_presented_token(record.plaintext_token)&.id
  end

  test "a JWT signed by someone else does not resolve" do
    record = build_token
    forged = JWT.encode(
      JWT.decode(record.wire_value, nil, false).first,
      OpenSSL::PKey::RSA.new(2048), "RS256", {kid: "whatever", typ: "at+jwt"}
    )

    assert_nil OidcAccessToken.find_by_presented_token(forged), "signature must be verified before lookup"
  end

  test "an expired JWT does not resolve" do
    record = build_token
    token = record.wire_value
    record.update!(expires_at: 2.hours.ago)

    travel_to 90.minutes.from_now do
      assert_nil OidcAccessToken.find_by_presented_token(token)
    end
  end

  test "garbage does not resolve and does not raise" do
    assert_nil OidcAccessToken.find_by_presented_token("not.a.jwt")
    assert_nil OidcAccessToken.find_by_presented_token("")
    assert_nil OidcAccessToken.find_by_presented_token(nil)
  end
end
