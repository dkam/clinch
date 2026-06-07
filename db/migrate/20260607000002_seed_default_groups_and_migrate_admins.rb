class SeedDefaultGroupsAndMigrateAdmins < ActiveRecord::Migration[8.1]
  # Data migration: seed "everyone" (auto_assign) and "admins" (admin) groups,
  # backfill memberships from existing data, attach "everyone" to previously
  # group-less applications. Idempotent.
  #
  # Must run before RemoveAdminFromUsers, because it reads the legacy
  # users.admin column.

  def up
    unless Group.exists?(auto_assign: true)
      everyone = Group.create!(
        name: "everyone",
        description: "Auto-assigned to new users. Safe to rename or remove.",
        auto_assign: true
      )

      User.where(status: 0).find_each do |u|
        UserGroup.find_or_create_by!(user_id: u.id, group_id: everyone.id)
      end

      Application.left_joins(:application_groups)
        .where(application_groups: {id: nil})
        .find_each do |app|
        ApplicationGroup.find_or_create_by!(application_id: app.id, group_id: everyone.id)
      end
    end

    unless Group.exists?(admin: true)
      admins = Group.create!(
        name: "admins",
        description: "Members can access the admin panel.",
        admin: true
      )

      User.where(admin: true).find_each do |u|
        UserGroup.find_or_create_by!(user_id: u.id, group_id: admins.id)
      end
    end
  end

  def down
    Group.where(name: ["everyone", "admins"]).destroy_all
  end
end
