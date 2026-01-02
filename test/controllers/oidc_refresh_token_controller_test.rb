require "test_helper"

class OidcRefreshTokenControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app)
    # Store a known client secret for testing
    @client_secret = SecureRandom.urlsafe_base64(48)
    @application.client_secret = @client_secret
    @application.save!
  end

  test "token endpoint returns refresh_token with authorization_code grant" do
    # Create an authorization code
    auth_code = OidcAuthorizationCode.create!(
      application: @application,
      user: @user,
      redirect_uri: @application.parsed_redirect_uris.first,
      scope: "openid profile email",
      expires_at: 10.minutes.from_now
    )

    # Exchange authorization code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: auth_code.plaintext_code,
      redirect_uri: @application.parsed_redirect_uris.first,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    json = JSON.parse(response.body)

    assert json["access_token"].present?
    assert json["id_token"].present?
    assert json["refresh_token"].present?
    assert_equal "Bearer", json["token_type"]
    assert_equal 3600, json["expires_in"]
  end

  test "refresh_token grant exchanges refresh token for new tokens" do
    # Create access and refresh tokens
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile email"
    )

    # Store the plaintext refresh token (available only during creation)
    plaintext_refresh_token = refresh_token.token

    # Use refresh token to get new tokens
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    json = JSON.parse(response.body)

    assert json["access_token"].present?
    assert json["id_token"].present?
    assert json["refresh_token"].present?
    assert_equal "Bearer", json["token_type"]

    # Old refresh token should be revoked
    assert refresh_token.reload.revoked?
  end

  test "refresh_token grant fails with expired refresh token" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile email",
      expires_at: 1.hour.ago  # Expired
    )

    plaintext_refresh_token = refresh_token.token

    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_equal "invalid_grant", json["error"]
  end

  test "refresh_token grant fails with revoked refresh token" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile email"
    )

    plaintext_refresh_token = refresh_token.token
    refresh_token.revoke!

    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_equal "invalid_grant", json["error"]
  end

  test "token revocation endpoint revokes access tokens" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    plaintext_access_token = access_token.plaintext_token

    post "/oauth/revoke", params: {
      token: plaintext_access_token,
      token_type_hint: "access_token",
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    assert access_token.reload.revoked?
  end

  test "token revocation endpoint revokes refresh tokens" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile email"
    )

    plaintext_refresh_token = refresh_token.token

    post "/oauth/revoke", params: {
      token: plaintext_refresh_token,
      token_type_hint: "refresh_token",
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    assert refresh_token.reload.revoked?
  end

  test "token rotation: new refresh token has same family id" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    old_refresh_token = OidcRefreshToken.create!(
      application: @application,
      user: @user,
      oidc_access_token: access_token,
      scope: "openid profile email"
    )

    family_id = old_refresh_token.token_family_id
    plaintext_refresh_token = old_refresh_token.token

    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: plaintext_refresh_token,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success

    # Find the new refresh token
    new_refresh_token = OidcRefreshToken.active.where(user: @user, application: @application).last
    assert_equal family_id, new_refresh_token.token_family_id
  end

  test "userinfo endpoint works with hashed access token" do
    access_token = OidcAccessToken.create!(
      application: @application,
      user: @user,
      scope: "openid profile email"
    )

    plaintext_token = access_token.plaintext_token

    get "/oauth/userinfo", headers: {
      "Authorization" => "Bearer #{plaintext_token}"
    }

    assert_response :success
    json = JSON.parse(response.body)

    # Should return pairwise SID from consent (alice has consent for kavita_app in fixtures)
    consent = OidcUserConsent.find_by(user: @user, application: @application)
    expected_sub = consent&.sid || @user.id.to_s
    assert_equal expected_sub, json["sub"]
    assert_equal @user.email_address, json["email"]
  end
end
