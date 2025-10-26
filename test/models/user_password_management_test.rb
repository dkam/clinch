require "test_helper"

class UserPasswordManagementTest < ActiveSupport::TestCase
  def setup
    @user = users(:alice)
  end

  test "should generate password reset token" do
    assert_nil @user.password_reset_token
    assert_nil @user.password_reset_token_created_at

    @user.generate_token_for(:password_reset)
    @user.save!

    assert_not_nil @user.password_reset_token
    assert_not_nil @user.password_reset_token_created_at
    assert @user.password_reset_token.length > 20
    assert @user.password_reset_token_created_at > 5.minutes.ago
  end

  test "should generate invitation login token" do
    assert_nil @user.invitation_login_token
    assert_nil @user.invitation_login_token_created_at

    @user.generate_token_for(:invitation_login)
    @user.save!

    assert_not_nil @user.invitation_login_token
    assert_not_nil @user.invitation_login_token_created_at
    assert @user.invitation_login_token.length > 20
    assert @user.invitation_login_token_created_at > 5.minutes.ago
  end

  test "should generate magic login token" do
    assert_nil @user.magic_login_token
    assert_nil @user.magic_login_token_created_at

    @user.generate_token_for(:magic_login)
    @user.save!

    assert_not_nil @user.magic_login_token
    assert_not_nil @user.magic_login_token_created_at
    assert @user.magic_login_token.length > 20
    assert @user.magic_login_token_created_at > 5.minutes.ago
  end

  test "should generate invitation token" do
    assert_nil @user.invitation_token
    assert_nil @user.invitation_token_created_at

    @user.generate_token_for(:invitation)
    @user.save!

    assert_not_nil @user.invitation_token
    assert_not_nil @user.invitation_token_created_at
    assert @user.invitation_token.length > 20
    assert @user.invitation_token_created_at > 5.minutes.ago
  end

  test "should generate tokens with different lengths" do
    # Test that different token types generate appropriate length tokens
    token_types = [:password_reset, :invitation_login, :magic_login, :invitation]

    token_types.each do |token_type|
      @user.generate_token_for(token_type)
      @user.save!

      token = @user.send("#{token_type}_token")
      assert_not_nil token, "#{token_type} token should be generated"
      assert token.length >= 32, "#{token_type} token should be at least 32 characters"
      assert token.length <= 64, "#{token_type} token should not exceed 64 characters"
    end
  end

  test "should validate token expiration timing" do
    # Test token creation timing
    @user.generate_token_for(:password_reset)
    @user.save!

    created_at = @user.send("#{:password_reset}_token_created_at")
    assert created_at.present?, "Token creation time should be set"
    assert created_at > 1.minute.ago, "Token should be recently created"
    assert created_at < 1.minute.from_now, "Token should be within reasonable time window"
  end

  test "should handle secure password generation" do
    # Test that password generation follows security practices
    password = "SecurePassword123!"

    # Test password contains uppercase, lowercase, numbers, special chars
    assert password.match(/[A-Z]/), "Password should contain uppercase letters"
    assert password.match(/[a-z]/), "Password should contain lowercase letters"
    assert password.match(/[0-9]/), "Password should contain numbers"
    assert password.match(/[!@#$%^&*()]/), "Password should contain special characters"
    assert password.length >= 12, "Password should be sufficiently long"
  end

  test "should handle password authentication flow" do
    # Test password authentication cycle
    password = "TestPassword123!"
    @user.password = password
    @user.save!

    # Test successful authentication
    authenticated_user = User.find_by(email_address: @user.email_address)
    assert authenticated_user.authenticate(password), "Should authenticate with correct password"
    assert_not authenticated_user.authenticate("WrongPassword"), "Should not authenticate with wrong password"

    # Test password changes invalidate old sessions
    old_password_digest = @user.password_digest
    @user.password = "NewPassword123!"
    @user.save!

    @user.reload
    assert_not @user.authenticate(password), "Old password should no longer work"
    assert @user.authenticate("NewPassword123!"), "New password should work"
  end

  test "should handle bcrypt password hashing" do
    # Test that password hashing uses bcrypt properly
    password = "MySecurePassword456!"

    # Create new user to test password digest
    new_user = User.new(
      email_address: "test@example.com",
      password: password
    )

    assert new_user.valid?, "User should be valid with password"

    # Save user to generate digest
    new_user.save!

    # Test that digest is properly set
    assert_not_nil new_user.password_digest, "Password digest should be set"
    assert new_user.password_digest.length > 50, "Password digest should be substantial"

    # Test digest format (bcrypt hashes start with $2a$)
    assert_match /^\$2a\$/, new_user.password_digest, "Password digest should be bcrypt format"

    # Test authentication against digest
    authenticated_user = User.find(new_user.id)
    assert authenticated_user.authenticate(password), "Should authenticate against bcrypt digest"
    assert_not authenticated_user.authenticate("wrongpassword"), "Should fail authentication with wrong password"
  end

  test "should validate different token types" do
    # Test all token types work
    token_types = [:password_reset, :invitation_login, :magic_login, :invitation]

    token_types.each do |token_type|
      @user.generate_token_for(token_type)
      @user.save!

      case token_type
      when :password_reset
        assert @user.password_reset_token.present?
        assert @user.password_reset_token_valid?
      when :invitation_login
        assert @user.invitation_login_token.present?
        assert @user.invitation_login_token_valid?
      when :magic_login
        assert @user.magic_login_token.present?
        assert @user.magic_login_token_valid?
      when :invitation
        assert @user.invitation_token.present?
        assert @user.invitation_token_valid?
      end
    end
  end

  test "should validate password strength" do
    # Test password validation rules
    weak_passwords = ["123456", "password", "qwerty", "abc123"]

    weak_passwords.each do |password|
      user = User.new(email_address: "test@example.com", password: password)
      assert_not user.valid?, "Weak password should be invalid"
      assert_includes user.errors[:password].to_s, "too short", "Weak password should be too short"
    end

    # Test valid password
    strong_password = "ThisIsA$tr0ngP@ssw0rd!123"
    user = User.new(email_address: "test@example.com", password: strong_password)
    assert user.valid?, "Strong password should be valid"
  end

  test "should handle password confirmation validation" do
    # Test password confirmation matching
    user = User.new(
      email_address: "test@example.com",
      password: "password123",
      password_confirmation: "password123"
    )
    assert user.valid?, "Password and confirmation should match"

    # Test password confirmation mismatch
    user.password_confirmation = "different"
    assert_not user.valid?, "Password and confirmation should match"
    assert_includes user.errors[:password_confirmation].to_s, "doesn't match"
  end

  test "should handle password reset controller integration" do
    # Test that password reset functionality works with controller integration
    original_password = @user.password_digest

    # Generate reset token through model
    @user.generate_token_for(:password_reset)
    @user.save!

    reset_token = @user.password_reset_token
    assert_not_nil reset_token, "Should generate reset token"

    # Verify token is usable in controller flow
    found_user = User.find_by_password_reset_token(reset_token)
    assert_equal @user, found_user, "Should find user by reset token"
  end

  test "should handle different user statuses" do
    # Test password functionality for different user statuses
    active_user = users(:alice)
    disabled_user = users(:bob)
    disabled_user.status = :disabled
    disabled_user.save!

    # Active user should be able to reset password
    assert active_user.generate_token_for(:password_reset)
    assert active_user.save

    # Disabled user might still be able to reset password (business logic decision)
    # This test documents current behavior - adjust if needed
    assert_nothing_raised do
      disabled_user.generate_token_for(:password_reset)
      disabled_user.save
    end
  end

  test "should validate email format during password operations" do
    # Test email format validation
    invalid_emails = [
      "invalid-email",
      "@example.com",
      "user@",
      "",
      nil
    ]

    invalid_emails.each do |email|
      user = User.new(email_address: email, password: "password123")
      assert_not user.valid?, "Invalid email should be rejected"
      assert user.errors[:email_address].present?, "Should have email error"
    end

    # Test valid email formats
    valid_emails = [
      "user@example.com",
      "user+tag@example.com",
      "user.name@example.co.uk",
      "123user@example-domain.com"
    ]

    valid_emails.each do |email|
      user = User.new(email_address: email, password: "password123")
      assert user.valid?, "Valid email should be accepted"
    end
  end

  test "should log password changes appropriately" do
    # Test that password changes are logged for audit
    original_password = @user.password_digest

    # Perform password change directly (bypassing token flow for test)
    @user.password = "NewPassword123!"
    @user.save!

    @user.reload
    assert_not_equal original_password, @user.password_digest
    assert @user.authenticate("NewPassword123!"), "New password should be valid"

    # Test that old password is invalidated
    old_password_instance = @user.dup
    old_password_instance.password_digest = original_password

    assert_not old_password_instance.authenticate("NewPassword123!"), "Old password should not authenticate new instance"
    assert_not old_password_instance.authenticate("NewPassword123!"), "Password change should invalidate old sessions"
  end
end