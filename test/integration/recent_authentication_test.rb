require "test_helper"

# Adding a way into an account (an API key, a passkey, an authenticator) asks
# for the password again unless the user signed in or confirmed it recently.
# The session cookie is shared with every app under the parent domain, so a
# compromised one could replay it; it must not be enough to make that access
# permanent. sign_in_as below sets exactly that cookie and nothing else.
class RecentAuthenticationTest < ActionDispatch::IntegrationTest
  setup do
    # Rails.cache is a :null_store in test; the throttle needs a real one.
    @original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new

    @user = users(:bob)
    @app = grant_everyone_access(Application.create!(name: "Key App", slug: "key-app", app_type: "forward_auth", domain_pattern: "keys.example.com", active: true))
  end

  teardown do
    Rails.cache = @original_cache
  end

  test "a session cookie alone can't create an API key" do
    sign_in_as(@user)

    get new_api_key_path
    assert_redirected_to "/reauthenticate"

    assert_no_difference -> { ApiKey.count } do
      post api_keys_path, params: {api_key: {name: "Replayed", application_id: @app.id}}
    end
    assert_redirected_to "/reauthenticate"
  end

  test "confirming the password allows it, and returns to where the user was" do
    sign_in_as(@user)
    get new_api_key_path

    post "/reauthenticate", params: {password: "password"}
    assert_redirected_to new_api_key_path

    get new_api_key_path
    assert_response :success
  end

  test "a wrong password allows nothing" do
    sign_in_as(@user)

    post "/reauthenticate", params: {password: "wrong"}
    assert_response :unprocessable_entity

    get new_api_key_path
    assert_redirected_to "/reauthenticate"
  end

  test "signing in counts as confirming the password, for a while" do
    post signin_path, params: {email_address: @user.email_address, password: "password"}

    get new_api_key_path
    assert_response :success

    travel 16.minutes do
      get new_api_key_path
      assert_redirected_to "/reauthenticate"
    end
  end

  test "adding a passkey needs a recent password" do
    sign_in_as(@user)

    post "/webauthn/challenge", as: :json

    assert_response :forbidden
    assert_equal "/reauthenticate", JSON.parse(response.body)["reauthenticate_url"]
  end

  test "enabling TOTP needs a recent password" do
    sign_in_as(@user)

    get new_totp_path

    assert_redirected_to "/reauthenticate"
  end

  test "confirming the password is throttled along with signing in" do
    sign_in_as(@user)
    SignInThrottle::LIMITS[:password].times { post "/reauthenticate", params: {password: "wrong"} }

    post "/reauthenticate", params: {password: "password"}

    get new_api_key_path
    assert_redirected_to "/reauthenticate"
  end
end
