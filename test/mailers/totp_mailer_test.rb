require "test_helper"

class TotpMailerTest < ActionMailer::TestCase
  test "enabled email addresses the user and names the event" do
    user = User.create!(email_address: "totp_mailer_test@example.com", password: "password123")

    email = TotpMailer.enabled(user)

    assert_equal ["totp_mailer_test@example.com"], email.to
    assert_equal "Two-factor authentication enabled on your account", email.subject
    text_body = email.text_part.body.to_s
    html_body = email.html_part.body.to_s
    assert_match "totp_mailer_test@example.com", text_body
    assert_match "totp_mailer_test@example.com", html_body
    assert_match(/Reset your password/i, text_body)

    user.destroy
  end
end
