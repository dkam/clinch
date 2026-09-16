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

    # --- Admin-initiated security events -------------------------------------
    # A user changing their own email is notified (profiles_controller); an admin
    # changing it for them must be too, or the highest-blast-radius mutation in
    # the product is the one that leaves no trace.

    test "admin changing a user's email notifies both the old and new address" do
      target = users(:bob)
      old_email = target.email_address

      assert_enqueued_emails 2 do
        patch admin_user_path(target), params: {
          user: {email_address: "bob-new@example.com"}
        }
      end

      assert_redirected_to admin_users_path
      assert_equal "bob-new@example.com", target.reload.email_address

      recipients = enqueued_security_mail_recipients
      assert_includes recipients, old_email
      assert_includes recipients, "bob-new@example.com"
    end

    test "admin update that leaves the email alone sends no email notification" do
      target = users(:bob)

      assert_no_enqueued_emails do
        patch admin_user_path(target), params: {
          user: {email_address: target.email_address, name: "Bobby"}
        }
      end

      assert_equal "Bobby", target.reload.name
    end

    test "granting admin group membership notifies the user and the other admins" do
      target = users(:bob)
      admin_group = groups(:admin_group)

      # alice and @admin (two) are already in admin_group via fixtures. The actor
      # is @admin, so the expected recipients are bob plus alice.
      assert_enqueued_emails 2 do
        patch admin_user_path(target), params: {
          user: {email_address: target.email_address, group_ids: [admin_group.id]}
        }
      end

      assert target.reload.admin?
      recipients = enqueued_security_mail_recipients
      assert_includes recipients, target.email_address
      assert_includes recipients, users(:alice).email_address
      assert_not_includes recipients, @admin.email_address, "the actor does not need telling"
    end

    test "revoking admin group membership notifies the user and the other admins" do
      target = users(:alice) # in admin_group via fixtures
      assert target.admin?

      assert_enqueued_emails 1 do
        patch admin_user_path(target), params: {
          user: {email_address: target.email_address, group_ids: [groups(:one).id]}
        }
      end

      assert_not target.reload.admin?
      assert_includes enqueued_security_mail_recipients, target.email_address
    end

    test "a non-admin group change sends no privilege notification" do
      target = users(:bob)

      assert_no_enqueued_emails do
        patch admin_user_path(target), params: {
          user: {email_address: target.email_address, group_ids: [groups(:editor_group).id]}
        }
      end

      assert_equal [groups(:editor_group)], target.reload.groups
    end

    private

    # Recipients of every SecurityMailer job sitting in the queue.
    def enqueued_security_mail_recipients
      enqueued_jobs.filter_map do |job|
        args = job[:args] || job["args"]
        next unless args.is_a?(Array)
        mailer, _method = args[0], args[1]
        next unless mailer == "SecurityMailer"
        params = args.find { |a| a.is_a?(Hash) && a.key?("args") }
        Array(params && params["args"]).filter_map { |a|
          a["recipient"] if a.is_a?(Hash)
        }
      end.flatten
    end
  end
end
