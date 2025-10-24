require "test_helper"

class UserRoleAssignmentTest < ActiveSupport::TestCase
  def setup
    @application = applications(:kavita_app)
    @role = @application.application_roles.create!(
      name: "admin",
      display_name: "Administrator"
    )
    @user = users(:alice)
    @assignment = UserRoleAssignment.create!(
      user: @user,
      application_role: @role
    )
  end

  test "should be valid" do
    assert @assignment.valid?
  end

  test "should enforce unique user-role combination" do
    duplicate_assignment = UserRoleAssignment.new(
      user: @user,
      application_role: @role
    )
    assert_not duplicate_assignment.valid?
    assert_includes duplicate_assignment.errors[:user], "has already been taken"
  end

  test "should allow same user with different roles" do
    other_role = @application.application_roles.create!(
      name: "editor",
      display_name: "Editor"
    )
    other_assignment = UserRoleAssignment.new(
      user: @user,
      application_role: other_role
    )
    assert other_assignment.valid?
  end

  test "should allow same role for different users" do
    other_user = users(:bob)
    other_assignment = UserRoleAssignment.new(
      user: other_user,
      application_role: @role
    )
    assert other_assignment.valid?
  end

  test "should validate source" do
    @assignment.source = "invalid_source"
    assert_not @assignment.valid?
    assert_includes @assignment.errors[:source], "is not included in the list"
  end

  test "should support valid sources" do %w[oidc manual group_sync].each do |source|
      @assignment.source = source
      assert @assignment.valid?, "Source '#{source}' should be valid"
    end
  end

  test "should default to oidc source" do
    new_assignment = UserRoleAssignment.new(
      user: @user,
      application_role: @role
    )
    assert_equal "oidc", new_assignment.source
  end

  test "should support metadata" do
    metadata = { "synced_at" => Time.current, "external_source" => "authentik" }
    @assignment.metadata = metadata
    @assignment.save
    assert_equal metadata, @assignment.reload.metadata
  end

  test "should identify oidc managed assignments" do
    @assignment.source = "oidc"
    assert @assignment.sync_from_oidc?
  end

  test "should not identify manually managed assignments as oidc" do
    @assignment.source = "manual"
    assert_not @assignment.sync_from_oidc?
  end
end