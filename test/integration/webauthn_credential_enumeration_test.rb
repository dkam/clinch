require "test_helper"

class WebauthnCredentialEnumerationTest < ActionDispatch::IntegrationTest
  # ====================
  # CREDENTIAL ENUMERATION PREVENTION TESTS
  # ====================

  test "prevents credential enumeration via delete endpoint" do
    user1 = User.create!(email_address: "user1@example.com", password: "password123")
    user2 = User.create!(email_address: "user2@example.com", password: "password123")

    # Create a credential for user1
    credential1 = user1.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("user1_credential"),
      public_key: Base64.urlsafe_encode64("public_key_1"),
      sign_count: 0,
      nickname: "User1 Key",
      authenticator_type: "platform"
    )

    # Create a credential for user2
    credential2 = user2.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("user2_credential"),
      public_key: Base64.urlsafe_encode64("public_key_2"),
      sign_count: 0,
      nickname: "User2 Key",
      authenticator_type: "platform"
    )

    # Sign in as user1
    post signin_path, params: { email_address: "user1@example.com", password: "password123" }
    assert_response :redirect
    follow_redirect!

    # Try to delete user2's credential while authenticated as user1
    # This should return 404 (not 403) to prevent enumeration
    delete webauthn_credential_path(credential2.id), as: :json

    assert_response :not_found
    assert_includes JSON.parse(@response.body)["error"], "not found"

    # Verify both credentials still exist
    assert_equal 1, user1.webauthn_credentials.count
    assert_equal 1, user2.webauthn_credentials.count

    # Verify trying to delete a non-existent credential also returns 404
    # This confirms identical responses for enumeration prevention
    delete webauthn_credential_path(99999), as: :json

    assert_response :not_found
    assert_includes JSON.parse(@response.body)["error"], "not found"

    user1.destroy
    user2.destroy
  end

  test "allows users to delete their own credentials" do
    user = User.create!(email_address: "user@example.com", password: "password123")

    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("user_credential"),
      public_key: Base64.urlsafe_encode64("public_key"),
      sign_count: 0,
      nickname: "My Key",
      authenticator_type: "platform"
    )

    # Sign in
    post signin_path, params: { email_address: "user@example.com", password: "password123" }
    assert_response :redirect
    follow_redirect!

    # Delete own credential - should succeed
    assert_difference "user.webauthn_credentials.count", -1 do
      delete webauthn_credential_path(credential.id), as: :json
    end

    assert_response :success
    assert_includes JSON.parse(@response.body)["message"], "has been removed"

    user.destroy
  end

  test "unauthenticated user cannot delete credentials" do
    user = User.create!(email_address: "user@example.com", password: "password123")

    credential = user.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("user_credential"),
      public_key: Base64.urlsafe_encode64("public_key"),
      sign_count: 0,
      nickname: "My Key",
      authenticator_type: "platform"
    )

    # Try to delete without authentication
    delete webauthn_credential_path(credential.id), as: :json

    # Should get redirect to signin (require_authentication before_action runs first)
    assert_response :redirect
    assert_redirected_to signin_path

    # Verify credential still exists
    assert_equal 1, user.webauthn_credentials.count

    user.destroy
  end
end
