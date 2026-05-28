require "test_helper"

module Admin
  class GroupsControllerTest < ActionDispatch::IntegrationTest
    setup do
      @admin = users(:two)
      sign_in_as(@admin)
      @group = groups(:one)
    end

    test "update assigns applications from application_ids" do
      app_a = applications(:kavita_app)
      app_b = applications(:another_app)

      patch admin_group_path(@group), params: {
        group: {
          name: @group.name,
          application_ids: [app_a.id, app_b.id]
        }
      }

      assert_redirected_to admin_group_path(@group)
      assert_equal [app_a, app_b].sort, @group.reload.applications.sort
    end

    test "update with no application_ids clears assigned applications" do
      @group.applications = [applications(:kavita_app)]

      patch admin_group_path(@group), params: {
        group: { name: @group.name }
      }

      assert_redirected_to admin_group_path(@group)
      assert_empty @group.reload.applications
    end

    test "create assigns applications from application_ids" do
      app = applications(:audiobookshelf_app)

      assert_difference -> { Group.count }, 1 do
        post admin_groups_path, params: {
          group: {
            name: "New Group",
            application_ids: [app.id]
          }
        }
      end

      assert_equal [app], Group.find_by(name: "new group").applications
    end
  end
end
