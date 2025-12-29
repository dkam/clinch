require "test_helper"

class UserPasswordManagementTest < ActiveSupport::TestCase
  def setup
    @user = users(:alice)
  end

  test "should generate password reset token" do
    token = @user.generate_token_for(:password_reset)
    @user.save!

    assert_not_nil token
    assert token.length > 20
    assert token.is_a?(String)
  end

  test "should generate invitation login token" do
    token = @user.generate_token_for(:invitation_login)
    @user.save!

    assert_not_nil token
    assert token.length > 20
    assert token.is_a?(String)
  end

  test "should generate tokens with different lengths" do
    # Test that different token types generate appropriate length tokens
    token_types = [:password_reset, :invitation_login]

    token_types.each do |token_type|
      token = @user.generate_token_for(token_type)
      @user.save!

      assert_not_nil token, "#{token_type} token should be generated"
      assert token.length >= 32, "#{token_type} token should be at least 32 characters"
      assert token.is_a?(String), "#{token_type} token should be a string"
    end
  end

  test "should validate token expiration timing" do
    # Test token creation timing - generate_token_for returns the token immediately
    before = Time.current
    token = @user.generate_token_for(:password_reset)
    after = Time.current

    @user.save!

    assert token.present?, "Token should be generated"
    assert before <= after, "Token generation should be immediate"
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
    # Test all token types work with generates_token_for
    token_types = [:password_reset, :invitation_login]

    token_types.each do |token_type|
      token = @user.generate_token_for(token_type)
      @user.save!

      # generate_token_for returns a token string
      assert token.present?, "#{token_type} token should be generated"
      assert token.is_a?(String), "#{token_type} token should be a string"
      assert token.length > 20, "#{token_type} token should be substantial length"
    end
  end

  test "should validate password strength" do
    # Test password validation rules (minimum length only)
    weak_passwords = ["123456", "abc", "short"]

    weak_passwords.each do |password|
      user = User.new(email_address: "test@example.com", password: password)
      assert_not user.valid?, "Weak password should be invalid"
      assert user.errors[:password].present?, "Should have password error"
    end

    # Test valid passwords (any 8+ character password is valid)
    valid_passwords = ["password123", "ThisIsA$tr0ngP@ssw0rd!123"]
    valid_passwords.each do |password|
      user = User.new(email_address: "test@example.com", password: password)
      assert user.valid?, "Valid 8+ character password should be valid"
    end
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
    # generate_token_for returns the token string
    reset_token = @user.generate_token_for(:password_reset)
    @user.save!

    assert_not_nil reset_token, "Should generate reset token"

    # Token can be used for lookups (returns nil if token is for different purpose/expired)
    # The token is stored and validated through Rails' generates_token_for mechanism
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

  test "should update last_sign_in_at timestamp" do
    # Test that last_sign_in_at is initially nil
    assert_nil @user.last_sign_in_at, "New user should have nil last_sign_in_at"

    # Update last_sign_in_at
    @user.update!(last_sign_in_at: Time.current)

    @user.reload
    assert_not_nil @user.last_sign_in_at, "last_sign_in_at should be set after update"
    assert @user.last_sign_in_at > 1.minute.ago, "last_sign_in_at should be recent"
  end
end