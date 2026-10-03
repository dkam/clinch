require "test_helper"
require "webauthn/fake_client"

# CLN-02 (September 2026 review): a passkey only counts as two factors when the
# authenticator verified the user (PIN or biometric). A touch proves possession
# and nothing else.
#   - registration requires user verification, so every new key is two factors;
#   - a touch-only key enrolled before that counts as one factor: acr "1" for a
#     user without 2FA, rejected on its own for a user with 2FA, and acceptable
#     as the second step once the password has been accepted.
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

  test "registration rejects an attestation that did not perform user verification" do
    # Asking for userVerification: "required" in the creation options is a
    # request to the client, not a guarantee: the gem only checks the UV flag
    # when `verify` is told to. An authenticator that ignores the request — or a
    # caller that never asked — would otherwise enroll a PIN-less key that then
    # signs in as acr "2". The options assertion above cannot catch this; only
    # verifying a real UV-less attestation can.
    user = users(:alice)
    sign_in_as(user)

    post "/webauthn/challenge"
    assert_response :success
    challenge = JSON.parse(response.body)["challenge"]

    client = WebAuthn::FakeClient.new("http://localhost")
    credential = client.create(challenge: challenge, user_verified: false)

    assert_no_difference -> { user.webauthn_credentials.count } do
      post "/webauthn/create", params: {credential: credential, nickname: "PIN-less key"}, as: :json
    end

    assert_response :unprocessable_entity
  end

  test "registration accepts an attestation that did perform user verification" do
    user = users(:alice)
    sign_in_as(user)

    post "/webauthn/challenge"
    assert_response :success
    challenge = JSON.parse(response.body)["challenge"]

    client = WebAuthn::FakeClient.new("http://localhost")
    credential = client.create(challenge: challenge, user_verified: true)

    assert_difference -> { user.webauthn_credentials.count }, 1 do
      post "/webauthn/create", params: {credential: credential, nickname: "PIN key"}, as: :json
    end

    assert_response :success
    assert_equal true, user.webauthn_credentials.find_by(nickname: "PIN key").user_verified
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
    # A user without 2FA may still sign in with a PIN-less roaming key, at one
    # factor, so the browser must not refuse to use it.
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

  test "a user without 2FA signs in with a touch-only passkey at one factor" do
    user = users(:alice)
    authenticator = enroll_passkey(user)

    assert_difference -> { user.sessions.count }, 1 do
      passkey_sign_in(user, authenticator, user_verified: false)
    end

    assert_response :success
    assert_equal "1", user.sessions.last.acr
    assert_equal false, user.webauthn_credentials.last.user_verified
  end

  test "a user without 2FA signs in with a passkey that verified them at two factors" do
    user = users(:alice)
    authenticator = enroll_passkey(user)

    passkey_sign_in(user, authenticator, user_verified: true)

    assert_response :success
    assert_equal "2", user.sessions.last.acr
  end

  test "a user who turned on 2FA cannot sign in with a touch-only passkey alone" do
    user = users(:alice)
    user.enable_totp!
    authenticator = enroll_passkey(user)

    assert_no_difference -> { user.sessions.count } do
      passkey_sign_in(user, authenticator, user_verified: false)
    end

    assert_response :unprocessable_entity
  end

  test "a 2FA-required user cannot sign in with a passkey alone if it did not verify them" do
    user = users(:alice)
    user.update!(totp_required: true)
    authenticator = enroll_passkey(user)

    assert_no_difference -> { user.sessions.count } do
      passkey_sign_in(user, authenticator, user_verified: false)
    end

    assert_response :unprocessable_entity
  end

  test "a 2FA-required user can sign in with a passkey that verified them" do
    user = users(:alice)
    user.update!(totp_required: true)
    authenticator = enroll_passkey(user)

    assert_difference -> { user.sessions.count }, 1 do
      passkey_sign_in(user, authenticator, user_verified: true)
    end

    assert_response :success
    assert_equal "2", user.sessions.last.acr
    assert_equal true, user.webauthn_credentials.last.user_verified
  end

  test "a 2FA-required user can use a touch-only passkey as the second factor after their password" do
    user = users(:alice)
    user.update!(totp_required: true)
    user.enable_totp!
    authenticator = enroll_passkey(user)

    post session_path, params: {email_address: user.email_address, password: "password"}
    assert_redirected_to totp_verification_path

    assert_difference -> { user.sessions.count }, 1 do
      passkey_sign_in(user, authenticator, user_verified: false)
    end

    assert_response :success
    assert_equal "2", user.sessions.last.acr
  end

  test "an expired password step does not count towards a touch-only passkey sign-in" do
    user = users(:alice)
    user.enable_totp!
    authenticator = enroll_passkey(user)

    post session_path, params: {email_address: user.email_address, password: "password"}
    assert_redirected_to totp_verification_path

    travel SessionsController::PENDING_SIGN_IN_TTL + 1.minute do
      assert_no_difference -> { user.sessions.count } do
        passkey_sign_in(user, authenticator, user_verified: false)
      end
    end

    assert_response :unprocessable_entity
  end

  test "a password accepted earlier does not carry over to a later touch-only passkey sign-in" do
    user = users(:alice)
    user.update!(totp_required: true)
    user.enable_totp!
    authenticator = enroll_passkey(user)

    post session_path, params: {email_address: user.email_address, password: "password"}
    passkey_sign_in(user, authenticator, user_verified: false)
    assert_response :success
    delete signout_path

    assert_no_difference -> { user.sessions.count } do
      passkey_sign_in(user, authenticator, user_verified: false)
    end

    assert_response :unprocessable_entity
  end

  test "authentication options require user verification for a 2FA-required user" do
    user = users(:alice)
    user.update!(totp_required: true)
    enroll_passkey(user)

    post "/sessions/webauthn/challenge", params: {email: user.email_address}
    assert_response :success

    assert_equal "required", JSON.parse(response.body)["userVerification"]
  end

  private

  # Stores a credential held by a fake authenticator, encoded the way
  # WebauthnController#create stores it, and returns the authenticator.
  def enroll_passkey(user)
    authenticator = WebAuthn::FakeClient.new("http://localhost")
    challenge = WebAuthn.configuration.encoder.encode(SecureRandom.random_bytes(32))
    credential = WebAuthn::Credential.from_create(authenticator.create(challenge: challenge, user_verified: true))
    credential.verify(challenge, user_verification: true)

    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64(credential.id),
      public_key: Base64.urlsafe_encode64(credential.public_key),
      sign_count: credential.sign_count,
      nickname: "test key"
    )
    authenticator
  end

  def passkey_sign_in(user, authenticator, user_verified:)
    post "/sessions/webauthn/challenge", params: {email: user.email_address}
    assert_response :success
    challenge = JSON.parse(response.body)["challenge"]

    assertion = authenticator.get(challenge: challenge, user_verified: user_verified)
    post "/sessions/webauthn/verify", params: {credential: assertion}, as: :json
  end
end
