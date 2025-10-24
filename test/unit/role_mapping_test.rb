require "test_helper"

class RoleMappingTest < ActiveSupport::TestCase
  self.use_transactional_tests = true

  # Don't load any fixtures
  def self.fixtures :all
    # Disable fixtures
  end
  # Test without fixtures for simplicity
  def setup
    @user = User.create!(
      email_address: "test@example.com",
      password: "password123",
      admin: false,
      status: :active
    )

    @application = Application.create!(
      name: "Test App",
      slug: "test-app",
      app_type: "oidc"
    )

    @admin_role = @application.application_roles.create!(
      name: "admin",
      display_name: "Administrator",
      description: "Full access user"
    )
  end

  def teardown
    UserRoleAssignment.delete_all
    ApplicationRole.delete_all
    Application.delete_all
    User.delete_all
  end

  test "should create application role" do
    assert @admin_role.valid?
    assert @admin_role.active?
    assert_equal "Administrator", @admin_role.display_name
  end

  test "should assign role to user" do
    assert_not @application.user_has_role?(@user, "admin")

    @application.assign_role_to_user!(@user, "admin", source: 'manual')

    assert @application.user_has_role?(@user, "admin")
    assert @admin_role.user_has_role?(@user)
  end

  test "should remove role from user" do
    @application.assign_role_to_user!(@user, "admin", source: 'manual')
    assert @application.user_has_role?(@user, "admin")

    @application.remove_role_from_user!(@user, "admin")
    assert_not @application.user_has_role?(@user, "admin")
  end

  test "should support role mapping modes" do
    assert_equal "disabled", @application.role_mapping_mode

    @application.update!(role_mapping_mode: "oidc_managed")
    assert @application.role_mapping_enabled?
    assert @application.oidc_managed_roles?

    @application.update!(role_mapping_mode: "hybrid")
    assert @application.hybrid_roles?
  end

  test "should sync roles from OIDC claims" do
    @application.update!(role_mapping_mode: "oidc_managed")

    claims = { "roles" => ["admin"] }
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "admin")
  end

  test "should filter roles by prefix" do
    @application.update!(role_prefix: "app-")
    @admin_role.update!(name: "app-admin")

    claims = { "roles" => ["app-admin", "external-role"] }
    RoleMappingEngine.sync_user_roles!(@user, @application, claims)

    assert @application.user_has_role?(@user, "app-admin")
  end

  test "should include roles in JWT tokens" do
    @application.assign_role_to_user!(@user, "admin", source: 'oidc')

    token = OidcJwtService.generate_id_token(@user, @application)
    decoded = JWT.decode(token, nil, false).first

    assert_includes decoded["roles"], "admin"
  end

  test "should support custom role claim name" do
    @application.update!(role_claim_name: "user_roles")
    @application.assign_role_to_user!(@user, "admin", source: 'oidc')

    token = OidcJwtService.generate_id_token(@user, @application)
    decoded = JWT.decode(token, nil, false).first

    assert_includes decoded["user_roles"], "admin"
    assert_nil decoded["roles"]
  end
end