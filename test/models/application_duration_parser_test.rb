require "test_helper"

class ApplicationDurationParserTest < ActiveSupport::TestCase
  test "access_token_ttl accepts human-friendly durations" do
    app = Application.new(access_token_ttl: "1h")
    assert_equal 3600, app.access_token_ttl

    app.access_token_ttl = "30m"
    assert_equal 1800, app.access_token_ttl

    app.access_token_ttl = "5m"
    assert_equal 300, app.access_token_ttl
  end

  test "refresh_token_ttl accepts human-friendly durations" do
    app = Application.new(refresh_token_ttl: "30d")
    assert_equal 2592000, app.refresh_token_ttl

    app.refresh_token_ttl = "1M"
    assert_equal 2592000, app.refresh_token_ttl

    app.refresh_token_ttl = "7d"
    assert_equal 604800, app.refresh_token_ttl
  end

  test "id_token_ttl accepts human-friendly durations" do
    app = Application.new(id_token_ttl: "1h")
    assert_equal 3600, app.id_token_ttl

    app.id_token_ttl = "2h"
    assert_equal 7200, app.id_token_ttl
  end

  test "TTL fields still accept plain numbers" do
    app = Application.new(
      access_token_ttl: 3600,
      refresh_token_ttl: 2592000,
      id_token_ttl: 3600
    )

    assert_equal 3600, app.access_token_ttl
    assert_equal 2592000, app.refresh_token_ttl
    assert_equal 3600, app.id_token_ttl
  end

  test "TTL fields accept plain number strings" do
    app = Application.new(
      access_token_ttl: "3600",
      refresh_token_ttl: "2592000",
      id_token_ttl: "3600"
    )

    assert_equal 3600, app.access_token_ttl
    assert_equal 2592000, app.refresh_token_ttl
    assert_equal 3600, app.id_token_ttl
  end

  test "invalid TTL values are set to nil" do
    app = Application.new(
      access_token_ttl: "invalid",
      refresh_token_ttl: "bad",
      id_token_ttl: "nope"
    )

    assert_nil app.access_token_ttl
    assert_nil app.refresh_token_ttl
    assert_nil app.id_token_ttl
  end

  test "validation still works with parsed values" do
    app = Application.new(
      name: "Test",
      slug: "test",
      app_type: "oidc",
      redirect_uris: "https://example.com/callback"
    )

    # Too short (below 5 minutes)
    app.access_token_ttl = "1m"
    assert_not app.valid?
    assert_includes app.errors[:access_token_ttl], "must be greater than or equal to 300"

    # Too long (above 24 hours for access token)
    app.access_token_ttl = "2d"
    assert_not app.valid?
    assert_includes app.errors[:access_token_ttl], "must be less than or equal to 86400"

    # Just right
    app.access_token_ttl = "1h"
    app.valid?  # Revalidate
    assert app.errors[:access_token_ttl].blank?
  end

  test "can create OIDC app with human-friendly TTL values" do
    app = Application.create!(
      name: "Test App",
      slug: "test-app",
      app_type: "oidc",
      redirect_uris: "https://example.com/callback",
      access_token_ttl: "1h",
      refresh_token_ttl: "30d",
      id_token_ttl: "2h"
    )

    assert_equal 3600, app.access_token_ttl
    assert_equal 2592000, app.refresh_token_ttl
    assert_equal 7200, app.id_token_ttl
  end
end
