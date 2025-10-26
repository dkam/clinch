require "test_helper"

class InvitationsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(
      email_address: "pending@example.com",
      password: "password123",
      status: :pending_invitation
    )
    @token = @user.generate_token_for(:invitation_login)
  end

  test "should show invitation form with valid token" do
    get invitation_path(@token)

    assert_response :success
    assert_select "h1", "Welcome to Clinch!"
    assert_select "form[action='#{invitation_path(@token)}']"
    assert_select "input[type='password'][name='password']"
    assert_select "input[type='password'][name='password_confirmation']"
  end

  test "should redirect to sign in with invalid token" do
    get invitation_path("invalid_token")

    assert_redirected_to signin_path
    assert_equal "Invitation link is invalid or has expired.", flash[:alert]
  end

  test "should redirect to sign in when user is not pending invitation" do
    active_user = User.create!(
      email_address: "active@example.com",
      password: "password123",
      status: :active
    )
    token = active_user.generate_token_for(:invitation_login)

    get invitation_path(token)

    assert_redirected_to signin_path
    assert_equal "This invitation has already been used or is no longer valid.", flash[:alert]
  end

  test "should accept invitation with valid password" do
    put invitation_path(@token), params: {
      password: "newpassword123",
      password_confirmation: "newpassword123"
    }

    assert_redirected_to root_path
    assert_equal "Your account has been set up successfully. Welcome!", flash[:notice]

    @user.reload
    assert_equal "active", @user.status
    assert @user.authenticate("newpassword123")
    assert cookies[:session_id] # Should be signed in
  end

  test "should reject invitation with password mismatch" do
    put invitation_path(@token), params: {
      password: "newpassword123",
      password_confirmation: "differentpassword"
    }

    assert_redirected_to invitation_path(@token)
    assert_equal "Passwords did not match.", flash[:alert]

    @user.reload
    assert_equal "pending_invitation", @user.status
    assert_nil cookies[:session_id] # Should not be signed in
  end

  test "should reject invitation with missing password" do
    put invitation_path(@token), params: {
      password: "",
      password_confirmation: ""
    }

    # When password validation fails, the controller should redirect back to the invitation form
    assert_redirected_to invitation_path(@token)
    assert_equal "Passwords did not match.", flash[:alert]

    @user.reload
    assert_equal "pending_invitation", @user.status
    assert_nil cookies[:session_id] # Should not be signed in
  end

  test "should reject invitation with short password" do
    put invitation_path(@token), params: {
      password: "short",
      password_confirmation: "short"
    }

    assert_redirected_to invitation_path(@token)
    assert_equal "Passwords did not match.", flash[:alert]

    @user.reload
    assert_equal "pending_invitation", @user.status
  end

  test "should destroy existing sessions when accepting invitation" do
    # Create an existing session for the user
    existing_session = @user.sessions.create!

    put invitation_path(@token), params: {
      password: "newpassword123",
      password_confirmation: "newpassword123"
    }

    assert_redirected_to root_path

    @user.reload
    assert_empty @user.sessions.where.not(id: @user.sessions.last) # Only new session should exist
  end

  test "should create new session after accepting invitation" do
    put invitation_path(@token), params: {
      password: "newpassword123",
      password_confirmation: "newpassword123"
    }

    assert_redirected_to root_path
    assert cookies[:session_id]

    @user.reload
    assert_equal 1, @user.sessions.count
  end

  test "should not allow invitation for disabled user" do
    disabled_user = User.create!(
      email_address: "disabled@example.com",
      password: "password123",
      status: :disabled
    )
    token = disabled_user.generate_token_for(:invitation_login)

    get invitation_path(token)

    assert_redirected_to signin_path
    assert_equal "This invitation has already been used or is no longer valid.", flash[:alert]
  end

  test "should allow access without authentication" do
    # This test ensures the allow_unauthenticated_access is working
    get invitation_path(@token)
    assert_response :success
  end
end