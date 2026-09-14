require "test_helper"

module Admin
  class ApplicationsControllerTest < ActionDispatch::IntegrationTest
    setup do
      @admin = users(:two)
      sign_in_as(@admin)

      @app = Application.create!(
        name: "WebDAV App",
        slug: "webdav-admin-app",
        app_type: "forward_auth",
        domain_pattern: "webdav.example.com",
        active: true
      )
      grant_everyone_access(@app)
    end

    test "show lists API keys issued against a forward auth application" do
      key = users(:bob).api_keys.create!(name: "rclone sync", application: @app)

      get admin_application_path(@app)

      assert_response :success
      assert_select "h3", text: /API Keys/
      assert_match key.name, response.body
      assert_match users(:bob).email_address, response.body
    end

    test "show marks a revoked key as revoked rather than hiding it" do
      key = users(:bob).api_keys.create!(name: "old laptop", application: @app)
      key.revoke!

      get admin_application_path(@app)

      assert_response :success
      assert_match "old laptop", response.body
      assert_select "span", text: "Revoked"
    end

    test "show does not list keys belonging to a different application" do
      other = Application.create!(
        name: "Other App",
        slug: "other-admin-app",
        app_type: "forward_auth",
        domain_pattern: "other.example.com",
        active: true
      )
      grant_everyone_access(other)
      users(:bob).api_keys.create!(name: "someone elses key", application: other)

      get admin_application_path(@app)

      assert_response :success
      assert_no_match "someone elses key", response.body
    end

    test "show omits the API keys panel for OIDC applications" do
      get admin_application_path(applications(:kavita_app))

      assert_response :success
      assert_select "h3", text: /API Keys/, count: 0
    end
  end
end
