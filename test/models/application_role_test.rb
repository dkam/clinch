require "test_helper"

class ApplicationRoleTest < ActiveSupport::TestCase
  def setup
    @application = applications(:kavita_app)
    @role = @application.application_roles.create!(
      name: "admin",
      display_name: "Administrator",
      description: "Full access to all features"
    )
  end

  test "should be valid" do
    assert @role.valid?
  end

  test "should require name" do
    @role.name = ""
    assert_not @role.valid?
    assert_includes @role.errors[:name], "can't be blank"
  end

  test "should require display_name" do
    @role.display_name = ""
    assert_not @role.valid?
    assert_includes @role.errors[:display_name], "can't be blank"
  end

  test "should enforce unique role name per application" do
    duplicate_role = @application.application_roles.build(
      name: @role.name,
      display_name: "Another Admin"
    )
    assert_not duplicate_role.valid?
    assert_includes duplicate_role.errors[:name], "has already been taken"
  end

  test "should allow same role name in different applications" do
    other_app = Application.create!(
      name: "Other App",
      slug: "other-app",
      app_type: "oidc"
    )
    other_role = other_app.application_roles.build(
      name: @role.name,
      display_name: "Other Admin"
    )
    assert other_role.valid?
  end

  test "should track user assignments" do
    user = users(:alice)
    assert_not @role.user_has_role?(user)

    @role.assign_to_user!(user)
    assert @role.user_has_role?(user)
    assert @role.users.include?(user)
  end

  test "should handle role removal" do
    user = users(:alice)
    @role.assign_to_user!(user)
    assert @role.user_has_role?(user)

    @role.remove_from_user!(user)
    assert_not @role.user_has_role?(user)
    assert_not @role.users.include?(user)
  end

  test "should default to active" do
    new_role = @application.application_roles.build(
      name: "member",
      display_name: "Member"
    )
    assert new_role.active?
  end

  test "should support default permissions" do
    role_with_permissions = @application.application_roles.create!(
      name: "editor",
      display_name: "Editor",
      permissions: { "read" => true, "write" => true, "delete" => false }
    )
    assert_equal({ "read" => true, "write" => true, "delete" => false }, role_with_permissions.permissions)
  end
end