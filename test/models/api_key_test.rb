require "test_helper"

class ApiKeyTest < ActiveSupport::TestCase
  setup do
    @user = users(:bob)
    @app = Application.create!(
      name: "WebDAV",
      slug: "webdav",
      app_type: "forward_auth",
      domain_pattern: "webdav.example.com",
      active: true
    )
  end

  test "generates clk_ prefixed token on create" do
    key = @user.api_keys.create!(name: "Test Key", application: @app)
    assert key.plaintext_token.start_with?("clk_")
    assert key.token_hmac.present?
  end

  test "find_by_token looks up via HMAC" do
    key = @user.api_keys.create!(name: "Test Key", application: @app)
    found = ApiKey.find_by_token(key.plaintext_token)
    assert_equal key.id, found.id
  end

  test "find_by_token returns nil for invalid token" do
    assert_nil ApiKey.find_by_token("clk_bogus")
    assert_nil ApiKey.find_by_token("")
    assert_nil ApiKey.find_by_token(nil)
  end

  test "active scope excludes revoked and expired keys" do
    active_key = @user.api_keys.create!(name: "Active", application: @app)
    revoked_key = @user.api_keys.create!(name: "Revoked", application: @app)
    revoked_key.revoke!
    expired_key = @user.api_keys.create!(name: "Expired", application: @app, expires_at: 1.day.ago)

    active_keys = @user.api_keys.active
    assert_includes active_keys, active_key
    assert_not_includes active_keys, revoked_key
    assert_not_includes active_keys, expired_key
  end

  test "active? expired? revoked? methods" do
    key = @user.api_keys.create!(name: "Test", application: @app)
    assert key.active?
    assert_not key.expired?
    assert_not key.revoked?

    key.revoke!
    assert_not key.active?
    assert key.revoked?

    key2 = @user.api_keys.create!(name: "Expiring", application: @app, expires_at: 1.hour.ago)
    assert_not key2.active?
    assert key2.expired?
  end

  test "nil expires_at means never expires" do
    key = @user.api_keys.create!(name: "No Expiry", application: @app, expires_at: nil)
    assert_not key.expired?
    assert key.active?
  end

  test "touch_last_used! updates timestamp" do
    key = @user.api_keys.create!(name: "Test", application: @app)
    assert_nil key.last_used_at
    key.touch_last_used!
    assert key.reload.last_used_at.present?
  end

  test "validates application must be forward_auth" do
    oidc_app = applications(:kavita_app)
    key = @user.api_keys.build(name: "Bad", application: oidc_app)
    assert_not key.valid?
    assert_includes key.errors[:application], "must be a forward auth application"
  end

  test "validates user must have access to application" do
    group = groups(:admin_group)
    @app.allowed_groups << group
    # @user (bob) is not in admin_group
    key = @user.api_keys.build(name: "No Access", application: @app)
    assert_not key.valid?
    assert_includes key.errors[:user], "does not have access to this application"
  end

  test "validates name presence" do
    key = @user.api_keys.build(name: "", application: @app)
    assert_not key.valid?
    assert_includes key.errors[:name], "can't be blank"
  end
end
