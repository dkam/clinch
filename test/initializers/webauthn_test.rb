require "test_helper"
require "minitest/mock"

# Passkeys are bound to the origin the browser reports and to an RP ID, the
# domain that owns them. Both come from the environment at boot, so these
# tests reload the initializer under different settings.
class WebauthnInitializerTest < ActiveSupport::TestCase
  INITIALIZER = Rails.root.join("config/initializers/webauthn.rb")

  teardown { load INITIALIZER }

  test "a CLINCH_HOST without a scheme still gives a working origin and RP ID" do
    boot_production_with("CLINCH_HOST" => "auth.example.com", "CLINCH_RP_ID" => nil)

    assert_equal ["https://auth.example.com"], WebAuthn.configuration.allowed_origins
    assert_equal "example.com", WebAuthn.configuration.rp_id
  end

  test "an RP ID that can't own passkeys for CLINCH_HOST gives way to one that can" do
    boot_production_with("CLINCH_HOST" => "https://auth.example.com", "CLINCH_RP_ID" => "localhost")

    assert_equal "example.com", WebAuthn.configuration.rp_id
  end

  test "a configured RP ID that fits CLINCH_HOST is kept" do
    boot_production_with("CLINCH_HOST" => "https://auth.example.com", "CLINCH_RP_ID" => "auth.example.com")

    assert_equal "auth.example.com", WebAuthn.configuration.rp_id
  end

  private

  def boot_production_with(env)
    original = env.keys.index_with { |key| ENV[key] }
    env.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }

    Rails.stub(:env, ActiveSupport::EnvironmentInquirer.new("production")) do
      load INITIALIZER
    end
  ensure
    original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end
end
