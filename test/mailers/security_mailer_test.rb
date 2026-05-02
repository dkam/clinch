require "test_helper"

class SecurityMailerTest < ActionMailer::TestCase
  CONTEXT = {
    ip: "203.0.113.42",
    user_agent: "Mozilla/5.0 (TestBrowser)",
    occurred_at: Time.utc(2026, 5, 2, 13, 37)
  }.freeze

  def setup
    @user = User.create!(email_address: "security_mailer_test@example.com", password: "password123")
  end

  def teardown
    @user.destroy
  end

  test "password_changed names the user and includes request metadata" do
    email = SecurityMailer.password_changed(@user, **CONTEXT)

    assert_equal [@user.email_address], email.to
    assert_match(/password was changed/i, email.subject)
    assert_bodies_contain email, @user.email_address
    assert_bodies_contain email, "203.0.113.42"
    assert_bodies_contain email, "TestBrowser"
  end

  test "totp_disabled describes the change" do
    email = SecurityMailer.totp_disabled(@user, **CONTEXT)

    assert_equal [@user.email_address], email.to
    assert_match(/two-factor.*disabled/i, email.subject)
    assert_bodies_contain email, "203.0.113.42"
  end

  test "backup_codes_regenerated mentions previous codes are invalid" do
    email = SecurityMailer.backup_codes_regenerated(@user, **CONTEXT)

    assert_match(/backup codes/i, email.subject)
    assert_bodies_match email, /previous backup codes are now invalid/i
  end

  test "passkey_added includes the nickname" do
    email = SecurityMailer.passkey_added(@user, nickname: "Yubikey-5", **CONTEXT)

    assert_match(/passkey.*added/i, email.subject)
    assert_bodies_contain email, "Yubikey-5"
  end

  test "passkey_removed includes the nickname" do
    email = SecurityMailer.passkey_removed(@user, nickname: "Old MacBook", **CONTEXT)

    assert_match(/passkey.*removed/i, email.subject)
    assert_bodies_contain email, "Old MacBook"
  end

  test "api_key_created includes the key name" do
    email = SecurityMailer.api_key_created(@user, name: "CI bot", **CONTEXT)

    assert_match(/api key.*created/i, email.subject)
    assert_bodies_contain email, "CI bot"
  end

  test "api_key_revoked includes the key name" do
    email = SecurityMailer.api_key_revoked(@user, name: "Old token", **CONTEXT)

    assert_match(/api key.*revoked/i, email.subject)
    assert_bodies_contain email, "Old token"
  end

  test "email_address_changed sent to new address confirms the new value" do
    email = SecurityMailer.email_address_changed(@user,
      recipient: "new@example.com",
      old_email: "old@example.com",
      new_email: "new@example.com",
      **CONTEXT)

    assert_equal ["new@example.com"], email.to
    assert_bodies_contain email, "new@example.com"
    assert_bodies_contain email, "old@example.com"
    assert_bodies_no_match email, /reset emails for the account/
  end

  test "email_address_changed sent to old address warns about reset emails" do
    email = SecurityMailer.email_address_changed(@user,
      recipient: "old@example.com",
      old_email: "old@example.com",
      new_email: "new@example.com",
      **CONTEXT)

    assert_equal ["old@example.com"], email.to
    assert_bodies_match email, /reset emails for the account/
  end

  private

  def assert_bodies_contain(email, fragment)
    assert_match fragment, email.text_part.body.to_s, "expected text body to contain #{fragment.inspect}"
    assert_match fragment, email.html_part.body.to_s, "expected html body to contain #{fragment.inspect}"
  end

  def assert_bodies_match(email, regex)
    assert_match regex, email.text_part.body.to_s
    assert_match regex, email.html_part.body.to_s
  end

  def assert_bodies_no_match(email, regex)
    refute_match regex, email.text_part.body.to_s
    refute_match regex, email.html_part.body.to_s
  end
end
