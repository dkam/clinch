require "test_helper"

# The profile scope's name claims fell back to the email address, which handed
# the address to clients granted profile but not email, and put an @ in
# preferred_username, which apps such as Gitea refuse.
class ProfileClaimsTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app) # alice_consent fixture
    @user.update!(username: nil, name: nil)
  end

  test "an ID token for profile without email doesn't contain the address" do
    payload = JWT.decode(OidcJwtService.generate_id_token(@user, @application, scopes: "openid profile"), nil, false).first

    assert_not payload.key?("preferred_username")
    assert_not payload.key?("name")
    assert_not_includes payload.values, @user.email_address
  end

  test "userinfo for profile without email doesn't contain the address" do
    token = OidcAccessToken.create!(application: @application, user: @user, scope: "openid profile")

    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}

    assert_response :success
    assert_not_includes response.body, @user.email_address
  end

  test "name falls back to the username, not the email address" do
    @user.update!(username: "alice")

    payload = JWT.decode(OidcJwtService.generate_id_token(@user, @application, scopes: "openid profile"), nil, false).first

    assert_equal "alice", payload["preferred_username"]
    assert_equal "alice", payload["name"]
  end
end
