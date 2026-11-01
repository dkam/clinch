require "test_helper"
require "open3"

# config/environments/development.rb is only read when booting development, so
# the way to know it works with Sentry switched on is to boot it.
class SentryDevelopmentBootTest < ActiveSupport::TestCase
  test "development boots with Sentry enabled" do
    env = {
      "RAILS_ENV" => "development",
      "SENTRY_DSN" => "http://public@127.0.0.1:9/1",
      "SENTRY_ENABLED_IN_DEVELOPMENT" => "true"
    }
    script = "print Sentry.initialized?, ' ', Sentry.configuration.enabled_in_current_env?"

    output, status = Open3.capture2e(env, "bin/rails", "runner", script, chdir: Rails.root.to_s)

    assert status.success?, output
    assert_equal "true true", output.lines.last.strip
  end
end
