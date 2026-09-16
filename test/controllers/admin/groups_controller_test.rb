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
        group: {name: @group.name}
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

    test "can mark a group as auto_assign and admin" do
      patch admin_group_path(@group), params: {
        group: {name: @group.name, auto_assign: "1", admin: "1"}
      }

      @group.reload
      assert @group.auto_assign?
      assert @group.admin?
    end

    test "cannot delete the last admin group" do
      admins = groups(:admin_group)

      delete admin_group_path(admins)
      # Destroy was aborted by the before_destroy guard
      assert Group.exists?(admins.id), "admin group should not have been deleted"
    end

    # Promotion is reachable from the group form as well as the user form:
    # flipping a plain group's `admin` flag promotes everyone already in it, in
    # one request. A notification that only fired on the user form would be
    # bypassable from here.

    test "flipping a group's admin flag notifies everyone it promotes" do
      plain = groups(:editor_group)
      plain.users = [users(:bob)]

      assert_enqueued_emails 2 do
        patch admin_group_path(plain), params: {
          group: {name: plain.name, admin: "1", user_ids: [users(:bob).id]}
        }
      end

      assert users(:bob).reload.admin?, "bob should have been promoted"
    end

    test "deleting an admin group notifies the members who lose access" do
      doomed = Group.create!(name: "Temp Admins", admin: true)
      doomed.users = [users(:bob)]
      assert users(:bob).reload.admin?

      # bob (demoted) plus alice (the other remaining admin); @admin is the
      # actor and is deliberately not told.
      assert_enqueued_emails 2 do
        delete admin_group_path(doomed)
      end

      assert_not users(:bob).reload.admin?
    end
  end
end
