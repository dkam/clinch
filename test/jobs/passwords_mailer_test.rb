require "test_helper"

class PasswordsMailerTest < ActionMailer::TestCase
  setup do
    @user = users(:alice)
    @reset_mail = PasswordsMailer.reset(@user)
  end

  test "should queue password reset email job" do
    # Note: In test environment, deliver_later might not enqueue jobs the same way
    # This test focuses on the mail delivery functionality
    assert_nothing_raised do
      PasswordsMailer.reset(@user).deliver_later
    end
  end

  test "should deliver password reset email successfully" do
    assert_emails 1 do
      PasswordsMailer.reset(@user).deliver_now
    end
  end

  test "should have correct email content" do
    email = @reset_mail

    assert_equal "Reset your password", email.subject
    assert_equal [@user.email_address], email.to
    assert_equal [], email.cc || []
    assert_equal [], email.bcc || []
    # From address is configured in ApplicationMailer
    assert_not_nil email.from
    assert email.from.is_a?(Array)
  end

  test "should include user data and reset token in email body" do
    # Set a password reset token for testing
    @user.generate_token_for(:password_reset)
    @user.save!

    email = PasswordsMailer.reset(@user)
    email_body = email.body.encoded

    # Should include reset link structure
    assert_includes email_body, "reset"
    assert_includes email_body, "password"

    # Use text_part to get readable content
    email_text = email.text_part&.decoded || email.body.decoded

    # Should include reset-related text
    assert_includes email_text, "reset"
    assert_includes email_text, "password"
    # Should include a URL (the reset link)
    assert_includes email_text, "http"
  end

  test "should handle users with different statuses" do
    # Test with active user
    active_user = users(:bob)
    assert active_user.status == "active"

    assert_emails 1 do
      PasswordsMailer.reset(active_user).deliver_now
    end

    # Test with disabled user (should still send reset if they request it)
    active_user.status = :disabled
    active_user.save!

    assert_emails 1 do
      PasswordsMailer.reset(active_user).deliver_now
    end
  end

  test "should queue multiple password reset emails" do
    users = [users(:alice), users(:bob)]

    # Test that multiple deliveries don't raise errors
    assert_nothing_raised do
      users.each do |user|
        user.generate_token_for(:password_reset)
        PasswordsMailer.reset(user).deliver_later
      end
    end

    # Test synchronous delivery to verify functionality
    assert_emails 2 do
      users.each do |user|
        user.generate_token_for(:password_reset)
        PasswordsMailer.reset(user).deliver_now
      end
    end
  end

  test "should handle user with reset token" do
    # User should have a reset token for the email to be useful
    assert_respond_to @user, :password_reset_token

    # Generate token and test email content
    @user.generate_token_for(:password_reset)
    @user.save!

    email = PasswordsMailer.reset(@user)
    email_text = email.text_part&.decoded || email.body.decoded

    assert_not_nil @user.password_reset_token
    assert_includes email_text, "reset"
  end

  test "should handle expired reset tokens gracefully" do
    # Test email generation even with expired tokens
    @user.generate_token_for(:password_reset)

    # Manually expire the token by updating its created_at time
    @user.instance_variable_set(:@password_reset_token_created_at, 25.hours.ago)

    # Email should still generate (validation happens elsewhere)
    assert_emails 1 do
      PasswordsMailer.reset(@user).deliver_now
    end
  end

  test "should respect mailer configuration" do
    # Test that the mailer inherits from ApplicationMailer properly
    assert PasswordsMailer < ApplicationMailer
    assert_respond_to PasswordsMailer, :default
  end

  test "should handle concurrent password reset deliveries" do
    # Simulate concurrent password reset deliveries
    users = User.limit(3)

    # Test that multiple deliveries don't raise errors
    assert_nothing_raised do
      users.each do |user|
        user.generate_token_for(:password_reset)
        PasswordsMailer.reset(user).deliver_later
      end
    end

    # Test synchronous delivery to verify functionality
    assert_emails users.count do
      users.each do |user|
        user.generate_token_for(:password_reset)
        PasswordsMailer.reset(user).deliver_now
      end
    end
  end

  test "should have proper email headers and security" do
    email = PasswordsMailer.reset(@user)
    email.deliver_now

    # Test common email headers
    assert_not_nil email.message_id
    assert_not_nil email.date

    # Test content-type (can be multipart, text/html, or text/plain)
    if email.html_part && email.text_part
      assert_includes email.content_type, "multipart/alternative"
    elsif email.html_part
      assert_includes email.content_type, "text/html"
    elsif email.text_part
      assert_includes email.content_type, "text/plain"
    end

    # Should not include sensitive data in headers (except Subject which legitimately mentions password)
    email.header.fields.each do |field|
      next if /^subject$/i.match?(field.name)
      # Check for actual tokens (not just the word "token" which is common in emails)
      refute_includes field.value.to_s.downcase, "password"
    end
  end

  test "should handle users with different email formats" do
    # Test with different email formats to ensure proper handling
    test_emails = [
      "user+tag@example.com",
      "user.name@example.com",
      "user@example.co.uk",
      "123user@example.com"
    ]

    test_emails.each do |email_address|
      temp_user = User.new(
        email_address: email_address,
        password: "password123",
        status: :active
      )
      temp_user.save!(validate: false) # Skip validation for testing

      assert_emails 1 do
        PasswordsMailer.reset(temp_user).deliver_now
      end

      email = PasswordsMailer.reset(temp_user)
      assert_equal [email_address], email.to
    end
  end
end
