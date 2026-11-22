require "test_helper"

# The 2FA form can arrive twice: a second click or Enter while the browser is
# still on its way to the app, or a password manager submitting it as well as
# the user. The first has signed the browser in by then, and the second used
# to send that signed-in user to /signin with "Session expired".
class TotpResubmissionTest < ActionDispatch::IntegrationTest
  setup do
    @app = applications(:another_app)
    @user = User.create!(email_address: "totp_resubmit@example.com", password: "password123")
    @user.enable_totp!
  end

  test "submitting the code again after it signed you in carries on to the app" do
    get "/oauth/authorize", params: {
      client_id: @app.client_id, response_type: "code", scope: "openid email profile",
      state: "spool-state", redirect_uri: "https://app.example.com/auth/callback"
    }
    assert_redirected_to signin_path

    post signin_path, params: {email_address: @user.email_address, password: "password123"}
    assert_redirected_to totp_verification_path

    post totp_verification_path, params: {code: ROTP::TOTP.new(@user.totp_secret).now}
    destination = response.location
    assert_match %r{/oauth/authorize\?}, destination

    post totp_verification_path, params: {code: ROTP::TOTP.new(@user.totp_secret).now}
    assert_redirected_to destination
    assert_nil flash[:alert]
    assert_equal 1, @user.sessions.count
  end

  test "coming back to the code page once signed in goes on, not to sign-in" do
    post signin_path, params: {email_address: @user.email_address, password: "password123"}
    post totp_verification_path, params: {code: ROTP::TOTP.new(@user.totp_secret).now}
    assert_redirected_to root_url

    get totp_verification_path
    assert_redirected_to root_url
    assert_nil flash[:alert]
  end
end
