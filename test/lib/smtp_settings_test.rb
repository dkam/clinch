require "test_helper"
require "clinch/smtp_settings"

class SmtpSettingsTest < ActiveSupport::TestCase
  test "a relay without a username is used without SMTP AUTH" do
    settings = Clinch::SmtpSettings.from_env("SMTP_ADDRESS" => "mail.internal")

    # With authentication set and no user name, the mail gem raises
    # "SMTP-AUTH requested but missing user name" and nothing is sent.
    assert_nil settings[:authentication]
    assert_nil settings[:user_name]
  end

  # compose.yaml passes every SMTP_* variable through, as an empty string when
  # it isn't set in .env.
  test "variables set to an empty string count as unset" do
    settings = Clinch::SmtpSettings.from_env(
      "SMTP_ADDRESS" => "", "SMTP_DOMAIN" => "", "SMTP_USERNAME" => "",
      "SMTP_PASSWORD" => "", "SMTP_AUTHENTICATION" => "plain"
    )

    assert_equal "localhost", settings[:address]
    assert_equal "localhost", settings[:domain]
    assert_nil settings[:authentication]
  end

  test "a username turns on SMTP AUTH, plain unless set" do
    settings = Clinch::SmtpSettings.from_env("SMTP_USERNAME" => "clinch", "SMTP_PASSWORD" => "secret")

    assert_equal "clinch", settings[:user_name]
    assert_equal "secret", settings[:password]
    assert_equal :plain, settings[:authentication]
    assert_equal :login, Clinch::SmtpSettings.from_env("SMTP_USERNAME" => "clinch", "SMTP_AUTHENTICATION" => "login")[:authentication]
  end

  test "STARTTLS is on unless turned off" do
    assert Clinch::SmtpSettings.from_env({})[:enable_starttls_auto]
    refute Clinch::SmtpSettings.from_env("SMTP_STARTTLS_AUTO" => "false")[:enable_starttls_auto]
  end
end
