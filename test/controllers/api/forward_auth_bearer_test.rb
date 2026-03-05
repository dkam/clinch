require "test_helper"

module Api
  class ForwardAuthBearerTest < ActionDispatch::IntegrationTest
    setup do
      @user = users(:bob)
      @app = Application.create!(
        name: "WebDAV App",
        slug: "webdav-app",
        app_type: "forward_auth",
        domain_pattern: "webdav.example.com",
        active: true
      )
      @api_key = @user.api_keys.create!(name: "Test Key", application: @app)
      @token = @api_key.plaintext_token
    end

    test "valid bearer token returns 200 with user headers" do
      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :ok
      assert_equal @user.email_address, response.headers["x-remote-user"]
      assert_equal @user.email_address, response.headers["x-remote-email"]
    end

    test "valid bearer token updates last_used_at" do
      assert_nil @api_key.last_used_at

      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :ok
      assert @api_key.reload.last_used_at.present?
    end

    test "expired bearer token returns 401 JSON" do
      @api_key.update_column(:expires_at, 1.hour.ago)

      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "Invalid or expired API key", json["error"]
    end

    test "revoked bearer token returns 401 JSON" do
      @api_key.revoke!

      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "Invalid or expired API key", json["error"]
    end

    test "invalid bearer token returns 401 JSON" do
      get "/api/verify", headers: {
        "Authorization" => "Bearer clk_totally_bogus_token",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "Invalid or expired API key", json["error"]
    end

    test "bearer token for wrong domain returns 401 JSON" do
      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "other.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "API key not valid for this domain", json["error"]
    end

    test "bearer token for inactive user returns 401 JSON" do
      @user.update!(status: :disabled)

      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "User account is not active", json["error"]
    end

    test "bearer token for inactive application returns 401 JSON" do
      @app.update!(active: false)

      get "/api/verify", headers: {
        "Authorization" => "Bearer #{@token}",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      json = JSON.parse(response.body)
      assert_equal "Application is inactive", json["error"]
    end

    test "no bearer token falls through to cookie auth" do
      # No auth header, no session -> should redirect (cookie flow)
      get "/api/verify", headers: {
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :redirect
      assert_match %r{/signin}, response.location
    end

    test "bearer token does not redirect on failure" do
      get "/api/verify", headers: {
        "Authorization" => "Bearer clk_bad",
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :unauthorized
      assert_equal "application/json", response.media_type
      # Should NOT be a redirect
      assert_nil response.headers["Location"]
    end

    test "cookie auth still works when no bearer token present" do
      sign_in_as(@user)

      get "/api/verify", headers: {
        "X-Forwarded-Host" => "webdav.example.com"
      }

      assert_response :ok
      assert_equal @user.email_address, response.headers["x-remote-user"]
    end
  end
end
