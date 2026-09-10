require "test_helper"

# CLN-02 (September 2026 review), staged:
#   1. record the UV flag on the credential so we can see what authenticators
#      actually do in this deployment;
#   2. require user verification at *registration*, so no new PIN-less key can
#      be enrolled (existing keys keep working);
#   3. later, once the logs show it is safe, require UV at login too.
#
# Until step 3, a passkey sign-in is still stamped acr "2"; the data gathered
# here is what decides when that becomes safe.
class WebauthnUserVerificationTest < ActionDispatch::IntegrationTest
  test "registration options require user verification" do
    user = users(:alice)
    sign_in_as(user)

    post "/webauthn/challenge"
    assert_response :success

    options = JSON.parse(response.body)
    assert_equal "required", options.dig("authenticatorSelection", "userVerification"),
      "a new key must not be enrollable without a PIN or biometric"
  end

  test "credentials record whether user verification was performed" do
    user = users(:alice)
    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("uv-test-cred"),
      public_key: Base64.urlsafe_encode64("key"),
      nickname: "uv test",
      sign_count: 0
    )

    assert_nil credential.user_verified, "unobserved credentials start as NULL, not false"

    credential.update_usage!(sign_count: 1, user_verified: true)
    assert_equal true, credential.reload.user_verified

    credential.update_usage!(sign_count: 2, user_verified: false)
    assert_equal false, credential.reload.user_verified
  end

  test "authentication options still allow existing keys without user verification" do
    # Step 2 only tightens registration. Requiring UV at login would lock out
    # anyone already carrying a PIN-less roaming key, which is what step 3 is
    # gated on.
    user = users(:alice)
    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("uv-login-cred"),
      public_key: Base64.urlsafe_encode64("key"),
      nickname: "uv login",
      sign_count: 0
    )

    post "/sessions/webauthn/challenge", params: {email: user.email_address}
    assert_response :success

    assert_equal "preferred", JSON.parse(response.body)["userVerification"]
  end
end
