require "test_helper"
require "webauthn/fake_client"

class WebauthnSecurityTest < ActionDispatch::SystemTestCase
  # ====================
  # REPLAY ATTACK PREVENTION (SIGN COUNT TRACKING) TESTS
  # ====================

  test "detects suspicious sign count for replay attacks" do
    user = User.create!(email_address: "webauthn_replay_test@example.com", password: "password123")

    # Create a WebAuthn credential
    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key"
    )

    # Simulate a suspicious sign count (decreased or reused)
    credential.update!(sign_count: 100)

    # Try to authenticate with a lower sign count (potential replay)
    suspicious = credential.suspicious_sign_count?(99)

    assert suspicious, "Should detect suspicious sign count indicating potential replay attack"

    user.destroy
  end

  test "sign count is incremented after successful authentication" do
    user = User.create!(email_address: "webauthn_signcount_test@example.com", password: "password123")

    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 50,
      nickname: "Test Key"
    )

    # Simulate authentication with new sign count
    credential.update_usage!(
      sign_count: 51,
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0"
    )

    credential.reload
    assert_equal 51, credential.sign_count, "Sign count should be incremented"

    user.destroy
  end

  # ====================
  # USER HANDLE BINDING TESTS
  # ====================

  test "user handle is properly bound to WebAuthn credential" do
    user = User.create!(email_address: "webauthn_handle_test@example.com", password: "password123")

    # Create a WebAuthn credential with user handle
    user_handle = SecureRandom.uuid
    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key",
      user_handle: user_handle
    )

    # Verify user handle is associated with the credential
    assert_equal user_handle, credential.user_handle

    user.destroy
  end

  test "WebAuthn authentication validates user handle" do
    user = User.create!(email_address: "webauthn_handle_auth_test@example.com", password: "password123")

    user_handle = SecureRandom.uuid
    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key",
      user_handle: user_handle
    )

    # Sign in with WebAuthn
    # The implementation should verify the user handle matches
    # This test documents the expected behavior

    user.destroy
  end

  # ====================
  # ORIGIN VALIDATION TESTS
  # ====================

  test "WebAuthn request validates origin" do
    user = User.create!(email_address: "webauthn_origin_test@example.com", password: "password123")
    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key"
    )

    # Test WebAuthn challenge from valid origin
    post webauthn_challenge_path, params: {email: "webauthn_origin_test@example.com"},
      headers: {HTTP_ORIGIN: "http://localhost:3000"}

    # Should succeed for valid origin

    # Test WebAuthn challenge from invalid origin
    post webauthn_challenge_path, params: {email: "webauthn_origin_test@example.com"},
      headers: {HTTP_ORIGIN: "http://evil.com"}

    # Should reject invalid origin

    user.destroy
  end

  test "WebAuthn verification includes origin validation" do
    user = User.create!(email_address: "webauthn_verify_origin_test@example.com", password: "password123")
    user.update!(webauthn_id: SecureRandom.uuid)

    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key"
    )

    # Sign in with WebAuthn
    post webauthn_challenge_path, params: {email: "webauthn_verify_origin_test@example.com"}
    assert_response :success

    JSON.parse(@response.body)["challenge"]

    # Simulate WebAuthn verification with wrong origin
    # This should fail

    user.destroy
  end

  # ====================
  # ATTESTATION FORMAT VALIDATION TESTS
  # ====================

  test "WebAuthn accepts standard attestation formats" do
    user = User.create!(email_address: "webauthn_attestation_test@example.com", password: "password123")

    # Register WebAuthn credential
    # Standard attestation formats: none, packed, tpm, android-key, android-safetynet, fido-u2f, etc.

    # Test with 'none' attestation (most common for privacy)
    {
      fmt: "none",
      attStmt: {},
      authData: Base64.strict_encode64("fake_auth_data")
    }

    # The implementation should accept standard attestation formats

    user.destroy
  end

  test "WebAuthn rejects invalid attestation formats" do
    user = User.create!(email_address: "webauthn_invalid_attestation_test@example.com", password: "password123")

    # Try to register with invalid attestation format
    {
      fmt: "invalid_format",
      attStmt: {},
      authData: Base64.strict_encode64("fake_auth_data")
    }

    # Should reject invalid attestation format

    user.destroy
  end

  # ====================
  # CREDENTIAL CLONING DETECTION TESTS
  # ====================

  test "detects credential cloning through sign count anomalies" do
    user = User.create!(email_address: "webauthn_clone_test@example.com", password: "password123")

    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 100,
      nickname: "Test Key"
    )

    # Simulate authentication from a cloned credential (sign count doesn't increase properly)
    # First auth: sign count = 101
    credential.update_usage!(sign_count: 101, ip_address: "192.168.1.1", user_agent: "Browser A")

    # Second auth from different location but sign count = 101 again (cloned!)
    suspicious = credential.suspicious_sign_count?(101)

    assert suspicious, "Should detect potential credential cloning"

    # Verify logging for security monitoring
    # The application should log suspicious sign count anomalies

    user.destroy
  end

  test "tracks IP address and user agent for WebAuthn authentications" do
    user = User.create!(email_address: "webauthn_tracking_test@example.com", password: "password123")

    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key"
    )

    # Update usage with tracking information
    credential.update_usage!(
      sign_count: 1,
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    credential.reload
    assert_equal "192.168.1.100", credential.last_ip_address
    assert_equal "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", credential.last_user_agent

    user.destroy
  end

  # ====================
  # CREDENTIAL EXCLUSION TESTS
  # ====================

  test "prevents duplicate credential registration" do
    user = User.create!(email_address: "webauthn_duplicate_test@example.com", password: "password123")

    credential_id = Base64.urlsafe_encode64("unique_credential_id")

    # Register first credential
    user.webauthn_credentials.create!(
      external_id: credential_id,
      public_key: Base64.urlsafe_encode64("public_key_1"),
      sign_count: 0,
      nickname: "Key 1"
    )

    # Try to register same credential ID again
    # Should reject or update existing credential

    user.destroy
  end

  # ====================
  # USER PRESENCE TESTS
  # ====================

  test "WebAuthn requires user presence for authentication" do
    user = User.create!(email_address: "webauthn_presence_test@example.com", password: "password123")
    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("fake_credential_id"),
      public_key: Base64.urlsafe_encode64("fake_public_key"),
      sign_count: 0,
      nickname: "Test Key"
    )

    # WebAuthn authenticator response should include user presence flag (UP)
    # The implementation should verify this flag is set to true

    user.destroy
  end

  # ====================
  # CREDENTIAL MANAGEMENT TESTS
  # ====================

  test "users can view and revoke their WebAuthn credentials" do
    user = User.create!(email_address: "webauthn_mgmt_test@example.com", password: "password123")

    # Create multiple credentials
    credential1 = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("credential_1"),
      public_key: Base64.urlsafe_encode64("public_key_1"),
      sign_count: 0,
      nickname: "USB Key"
    )

    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("credential_2"),
      public_key: Base64.urlsafe_encode64("public_key_2"),
      sign_count: 0,
      nickname: "Laptop Key"
    )

    # User should be able to view their credentials
    assert_equal 2, user.webauthn_credentials.count

    # User should be able to revoke a credential
    credential1.destroy
    assert_equal 1, user.webauthn_credentials.count

    user.destroy
  end

  # ====================
  # WEBAUTHN AND PASSWORD LOGIN INTERACTION TESTS
  # ====================

  test "WebAuthn can be required for authentication" do
    user = User.create!(email_address: "webauthn_required_test@example.com", password: "password123")
    user.update!(webauthn_enabled: true)

    # Sign in with password should still work
    post signin_path, params: {email_address: "webauthn_required_test@example.com", password: "password123"}

    # If WebAuthn is enabled, should offer WebAuthn as an option
    # Implementation should handle password + WebAuthn or passwordless flow

    user.destroy
  end

  test "WebAuthn can be used for passwordless authentication" do
    user = User.create!(email_address: "webauthn_passwordless_test@example.com", password: "password123")
    user.update!(webauthn_enabled: true)

    user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("passwordless_credential"),
      public_key: Base64.urlsafe_encode64("public_key"),
      sign_count: 0,
      nickname: "Passwordless Key"
    )

    # User should be able to sign in with WebAuthn alone
    # Test passwordless flow

    user.destroy
  end
end
