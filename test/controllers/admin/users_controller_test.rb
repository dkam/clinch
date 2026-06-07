require "test_helper"

module Admin
  class UsersControllerTest < ActionDispatch::IntegrationTest
    setup do
      @admin = users(:two) # in admin_group via fixtures
      sign_in_as(@admin)
    end

    test "show loads accessible applications via the user's groups" do
      kavita = applications(:kavita_app)
      # alice is in admin_group via fixtures; kavita is attached to admin_group via app_groups
      get admin_user_path(users(:alice))
      assert_response :success
      assert_match kavita.name, response.body
      # The "via" badge mentions the granting group name
      assert_match groups(:admin_group).name, response.body
    end

    test "update assigns group memberships from group_ids" do
      target = users(:bob)
      editors = groups(:editor_group)
      one = groups(:one)

      patch admin_user_path(target), params: {
        user: {email_address: target.email_address, group_ids: [editors.id, one.id]}
      }

      assert_redirected_to admin_users_path
      assert_equal [editors, one].sort, target.reload.groups.sort
    end

    test "cannot remove yourself from the last admin group" do
      # @admin (users:two) is in admin_group. Removing them via the user form
      # while no other admin exists is blocked.
      sole_admin = users(:two)
      # Strip alice (the other admin) so @admin is the last one.
      users(:alice).groups.delete(groups(:admin_group))

      patch admin_user_path(sole_admin), params: {
        user: {email_address: sole_admin.email_address, group_ids: []}
      }

      assert_response :unprocessable_entity
      assert sole_admin.reload.admin?, "should still be admin"
    end

    test "create with auto_assign=0 skips the auto-assign callback" do
      post admin_users_path, params: {
        user: {email_address: "restricted@example.com"},
        auto_assign: "0"
      }

      assert_response :redirect
      created = User.find_by(email_address: "restricted@example.com")
      assert_not_includes created.groups, groups(:everyone)
    end

    test "create without auto_assign param auto-joins everyone" do
      post admin_users_path, params: {
        user: {email_address: "newbie@example.com"}
      }

      assert_response :redirect
      created = User.find_by(email_address: "newbie@example.com")
      assert_includes created.groups, groups(:everyone)
    end
  end
end
