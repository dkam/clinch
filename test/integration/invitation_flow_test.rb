require "test_helper"

class InvitationFlowTest < ActionDispatch::IntegrationTest
  test "complete invitation flow from email to account setup" do
    # Create a pending user (simulating admin invitation)
    user = User.create!(
      email_address: "newuser@example.com",
      password: "temppassword",
      status: :pending_invitation
    )

    # Generate invitation token (simulating email link)
    token = user.generate_token_for(:invitation_login)

    # Step 1: User clicks invitation link
    get invitation_path(token)
    assert_response :success
    assert_select "h1", "Welcome to Clinch!"

    # Step 2: User submits valid password
    put invitation_path(token), params: {
      password: "SecurePassword123!",
      password_confirmation: "SecurePassword123!"
    }

    # Should be redirected to dashboard
    assert_redirected_to root_path
    assert_equal "Your account has been set up successfully. Welcome!", flash[:notice]

    # Verify user is now active and signed in
    user.reload
    assert_equal "active", user.status
    assert user.authenticate("SecurePassword123!")
    assert cookies[:session_id]

    # Step 3: User can now access protected areas
    get root_path
    assert_response :success

    # Step 4: User can sign out and sign back in with new password
    delete session_path
    assert_redirected_to signin_path
    # Cookie might still be present but session should be invalid
    # Check that we can't access protected resources
    get root_path
    assert_redirected_to signin_path

    post signin_path, params: {
      email_address: "newuser@example.com",
      password: "SecurePassword123!"
    }
    # Redirect may include fa_token parameter for first-time authentication
    assert_response :redirect
    assert_match %r{^http://www\.example\.com/}, response.location
    assert cookies[:session_id]
  end

  test "invitation flow with password validation error" do
    user = User.create!(
      email_address: "user@example.com",
      password: "temppassword",
      status: :pending_invitation
    )

    token = user.generate_token_for(:invitation_login)

    # Visit invitation page
    get invitation_path(token)
    assert_response :success

    # Submit mismatching passwords
    put invitation_path(token), params: {
      password: "Password123!",
      password_confirmation: "DifferentPassword123!"
    }

    # Should redirect back to invitation form with error
    assert_redirected_to invitation_path(token)
    assert_equal "Passwords did not match.", flash[:alert]

    # User should still be pending invitation
    user.reload
    assert_equal "pending_invitation", user.status

    # User should not be signed in
    # Cookie might still be present but session should be invalid
    # Check that we can't access protected resources
    get root_path
    assert_redirected_to signin_path

    # Try to access protected area - should be redirected
    get root_path
    assert_redirected_to signin_path
  end

  test "expired invitation token flow" do
    user = User.create!(
      email_address: "expired@example.com",
      password: "temppassword",
      status: :pending_invitation
    )

    # Simulate expired token by creating a manually crafted invalid token
    invalid_token = "expired_token_#{SecureRandom.hex(20)}"

    get invitation_path(invalid_token)
    assert_redirected_to signin_path
    assert_equal "Invitation link is invalid or has expired.", flash[:alert]
  end

  test "invitation for already active user" do
    user = User.create!(
      email_address: "active@example.com",
      password: "password123",
      status: :active
    )

    token = user.generate_token_for(:invitation_login)

    get invitation_path(token)
    assert_redirected_to signin_path
    assert_equal "This invitation has already been used or is no longer valid.", flash[:alert]
  end

  test "multiple invitation attempts" do
    user = User.create!(
      email_address: "multiple@example.com",
      password: "temppassword",
      status: :pending_invitation
    )

    token = user.generate_token_for(:invitation_login)

    # First attempt - wrong password
    put invitation_path(token), params: {
      password: "wrong",
      password_confirmation: "wrong"
    }
    assert_redirected_to invitation_path(token)
    assert_equal "Passwords did not match.", flash[:alert]

    # Second attempt - successful
    put invitation_path(token), params: {
      password: "CorrectPassword123!",
      password_confirmation: "CorrectPassword123!"
    }
    assert_redirected_to root_path
    assert_equal "Your account has been set up successfully. Welcome!", flash[:notice]

    user.reload
    assert_equal "active", user.status
  end

  test "invitation flow with session cleanup" do
    user = User.create!(
      email_address: "cleanup@example.com",
      password: "temppassword",
      status: :pending_invitation
    )

    # Create existing sessions
    old_session1 = user.sessions.create!
    old_session2 = user.sessions.create!
    assert_equal 2, user.sessions.count

    token = user.generate_token_for(:invitation_login)

    put invitation_path(token), params: {
      password: "NewPassword123!",
      password_confirmation: "NewPassword123!"
    }

    assert_redirected_to root_path

    user.reload
    # Should have only one new session
    assert_equal 1, user.sessions.count
    assert_not_equal old_session1.id, user.sessions.first.id
    assert_not_equal old_session2.id, user.sessions.first.id
  end
end