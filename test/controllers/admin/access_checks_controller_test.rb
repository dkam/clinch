require "test_helper"

module Admin
  class AccessChecksControllerTest < ActionDispatch::IntegrationTest
    setup do
      @admin = users(:two)
      sign_in_as(@admin)
      @kavita = applications(:kavita_app)
    end

    test "new renders the form with users and applications" do
      get admin_access_path
      assert_response :success
      assert_match @kavita.name, response.body
      assert_match "alice@example.com", response.body
    end

    test "create returns 'can access' with via group when user is in an allowed group" do
      post admin_access_path, params: {
        user_id: users(:alice).id,
        application_id: @kavita.id
      }
      assert_response :success
      assert_match "can access", response.body
      assert_match "Administrators", response.body # alice is in admin_group; kavita has admin_group
    end

    test "create returns 'cannot access' with reason when user shares no group with the app" do
      lonely = User.create!(email_address: "lonely@example.com", password: "password123", skip_auto_assign: true)
      post admin_access_path, params: {
        user_id: lonely.id,
        application_id: @kavita.id
      }
      assert_response :success
      assert_match "cannot access", response.body
      assert_match "shares no group", response.body
    end

    test "create renders form unchanged when ids are missing" do
      post admin_access_path, params: {user_id: "", application_id: ""}
      assert_response :success
      # No result panel should render. The panel-only phrases:
      refute_match "Granted via", response.body
      refute_match "Reason:", response.body
    end
  end
end
