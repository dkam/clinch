require "test_helper"

class RoleMappingEngineTest < ActiveSupport::TestCase
  def setup
    @application = applications(:kavita_app)
    @user = users(:alice)
    @application.update!(
      role_mapping_mode: "oidc_managed",
      role_claim_name: "roles"
    )

    @admin_role = @application.application_roles.create!(
      name: "admin",
      display_name: "Administrator"
    )
    @editor_role = @application.application_roles.create!(
      name: "editor",
      display_name: "Editor"
    )
  end

  test "should sync user roles from claims" do
    claims = { "roles" => ["admin", "editor"] }

    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
    assert @application.user_has_role?(@user, "editor")
  end

  test "should remove roles not present in claims for oidc managed" do
    # Assign initial roles
    @application.assign_role_to_user!(@user, "admin", source: 'oidc')
    @application.assign_role_to_user!(@user, "editor", source: 'oidc')

    # Sync with only admin role
    claims = { "roles" => ["admin"] }
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
    assert_not @application.user_has_role?(@user, "editor")
  end

  test "should handle hybrid mode role sync" do
    @application.update!(role_mapping_mode: "hybrid")

    # Assign manual role first
    @application.assign_role_to_user!(@user, "editor", source: 'manual')

    # Sync with admin role from OIDC
    claims = { "roles" => ["admin"] }
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
    assert @application.user_has_role?(@user, "editor") # Manual role preserved
  end

  test "should filter roles by prefix" do
    @application.update!(role_prefix: "app-")
    @admin_role.update!(name: "app-admin")
    @editor_role.update!(name: "app-editor")

    # Create non-matching role
    external_role = @application.application_roles.create!(
      name: "external-role",
      display_name: "External"
    )

    claims = { "roles" => ["app-admin", "app-editor", "external-role"] }
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "app-admin")
    assert @application.user_has_role?(@user, "app-editor")
    assert_not @application.user_has_role?(@user, "external-role")
  end

  test "should handle different claim names" do
    @application.update!(role_claim_name: "groups")
    claims = { "groups" => ["admin", "editor"] }

    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
    assert @application.user_has_role?(@user, "editor")
  end

  test "should handle microsoft role claim format" do
    microsoft_claim = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    claims = { microsoft_claim => ["admin", "editor"] }

    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
    assert @application.user_has_role?(@user, "editor")
  end

  test "should determine user access based on roles" do
    # OIDC managed mode - user needs roles to access
    claims = { "roles" => ["admin"] }
    assert RoleMappingEngine.user_allowed_with_roles?(@user, @application, claims)

    # No roles should deny access
    empty_claims = { "roles" => [] }
    assert_not RoleMappingEngine.user_allowed_with_roles?(@user, @application, empty_claims)
  end

  test "should handle hybrid mode access control" do
    @application.update!(role_mapping_mode: "hybrid")

    # User with group access should be allowed
    group_access = @application.user_allowed?(@user)
    assert RoleMappingEngine.user_allowed_with_roles?(@user, @application)

    # User with role access should be allowed
    claims = { "roles" => ["admin"] }
    assert RoleMappingEngine.user_allowed_with_roles?(@user, @application, claims)

    # User without either should be denied
    empty_claims = { "roles" => [] }
    result = RoleMappingEngine.user_allowed_with_roles?(@user, @application, empty_claims)
    # Should be allowed if group access exists, otherwise denied
    assert_equal group_access, result
  end

  test "should map external roles to internal roles" do
    external_roles = ["admin", "editor", "unknown-role"]

    mapped_roles = RoleMappingEngine.map_external_to_internal_roles(@application, external_roles)

    assert_includes mapped_roles, "admin"
    assert_includes mapped_roles, "editor"
    assert_not_includes mapped_roles, "unknown-role"
  end

  test "should extract roles from various claim formats" do
    # Array format
    claims_array = { "roles" => ["admin", "editor"] }
    roles = RoleMappingEngine.send(:extract_roles_from_claims, @application, claims_array)
    assert_equal ["admin", "editor"], roles

    # String format
    claims_string = { "roles" => "admin" }
    roles = RoleMappingEngine.send(:extract_roles_from_claims, @application, claims_string)
    assert_equal ["admin"], roles

    # No roles
    claims_empty = { "other_claim" => "value" }
    roles = RoleMappingEngine.send(:extract_roles_from_claims, @application, claims_empty)
    assert_equal [], roles
  end

  test "should handle disabled role mapping" do
    @application.update!(role_mapping_mode: "disabled")
    claims = { "roles" => ["admin"] }

    # Should not sync roles when disabled
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)
    assert_not @application.user_has_role?(@user, "admin")

    # Should fall back to regular access control
    assert RoleMappingEngine.user_allowed_with_roles?(@user, @application, claims)
  end
end