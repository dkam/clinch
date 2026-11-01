require "test_helper"
require "sentry/test_helper"

# What leaves the building when Sentry is on. Clinch carries authorization
# codes, state and tokens in query strings, cookies and request bodies, so an
# event must arrive without any of them, whatever the SDK's own defaults are.
class SentryInitializerTest < ActiveSupport::TestCase
  include Sentry::TestHelper

  setup do
    @dsn = ENV["SENTRY_DSN"]
    ENV["SENTRY_DSN"] = "http://public@127.0.0.1:9/1"
    load Rails.root.join("config/initializers/sentry.rb")
    setup_sentry_test
  end

  teardown do
    teardown_sentry_test
    Sentry.close
    ENV["SENTRY_DSN"] = @dsn
  end

  test "request query string, cookies, credentials, body and client address are not sent" do
    env = Rack::MockRequest.env_for(
      "https://clinch.example.com/oauth/token?code=secret-code&state=secret-state",
      :method => "POST",
      :input => "client_secret=secret-body",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded",
      "HTTP_COOKIE" => "session_id=secret-cookie",
      "HTTP_AUTHORIZATION" => "Basic secret-basic-auth",
      "HTTP_X_FORWARDED_FOR" => "203.0.113.7",
      "REMOTE_ADDR" => "203.0.113.7"
    )

    Sentry.with_scope do |scope|
      scope.set_rack_env(env)
      Sentry.capture_message("boom")
    end

    # Thread stack frames quote this file's source lines, secrets included.
    payload = last_sentry_event.to_h.except(:threads).to_json
    %w[secret-code secret-state secret-cookie secret-basic-auth secret-body 203.0.113.7].each do |leak|
      refute_includes payload, leak, "#{leak} was sent to Sentry"
    end
  end

  test "extra context with sensitive keys is dropped" do
    Sentry.capture_message("boom", extra: {access_token: "abc", client: "kept"})

    extra = last_sentry_event.extra
    assert_equal "kept", extra[:client]
    refute extra.key?(:access_token)
  end
end
