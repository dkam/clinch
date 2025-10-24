require "test_helper"

class OidcRoleMappingTest < ActionDispatch::IntegrationTest
  def setup
    @application = applications(:kavita_app)
    @user = users(:alice)

    # Set a known client secret for testing
    @test_client_secret = "test_secret_for_testing_only"
    @application.client_secret = @test_client_secret
    @application.save!

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

    sign_in @user
  end

  test "should include roles in JWT tokens" do
    # Assign roles to user
    @application.assign_role_to_user!(@user, "admin", source: 'oidc')
    @application.assign_role_to_user!(@user, "editor", source: 'oidc')

    # Get authorization code
    post oauth_authorize_path, params: {
      client_id: @application.client_id,
      response_type: "code",
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state",
      nonce: "test-nonce"
    }

    follow_redirect!
    post oauth_consent_path, params: {
      consent: "approve",
      client_id: @application.client_id,
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    assert_response :redirect
    authorization_code = extract_code_from_redirect(response.location)

    # Exchange code for token
    post oauth_token_path, params: {
      grant_type: "authorization_code",
      code: authorization_code,
      redirect_uri: "https://example.com/callback",
      client_id: @application.client_id,
      client_secret: @test_client_secret
    }

    assert_response :success
    token_response = JSON.parse(response.body)
    id_token = token_response["id_token"]

    # Decode and verify ID token contains roles
    decoded_token = JWT.decode(id_token, nil, false).first
    assert_includes decoded_token["roles"], "admin"
    assert_includes decoded_token["roles"], "editor"
  end

  test "should filter roles by prefix" do
    @application.update!(role_prefix: "app-")
    @admin_role.update!(name: "app-admin")
    @editor_role.update!(name: "external-editor") # Should be filtered out

    @application.assign_role_to_user!(@user, "app-admin", source: 'oidc')
    @application.assign_role_to_user!(@user, "external-editor", source: 'oidc')

    # Get token
    post oauth_authorize_path, params: {
      client_id: @application.client_id,
      response_type: "code",
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    follow_redirect!
    post oauth_consent_path, params: {
      consent: "approve",
      client_id: @application.client_id,
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    authorization_code = extract_code_from_redirect(response.location)

    post oauth_token_path, params: {
      grant_type: "authorization_code",
      code: authorization_code,
      redirect_uri: "https://example.com/callback",
      client_id: @application.client_id,
      client_secret: @test_client_secret
    }

    token_response = JSON.parse(response.body)
    id_token = token_response["id_token"]
    decoded_token = JWT.decode(id_token, nil, false).first

    assert_includes decoded_token["roles"], "app-admin"
    assert_not_includes decoded_token["roles"], "external-editor"
  end

  test "should include role permissions when configured" do
    @application.update!(managed_permissions: { "include_permissions" => true })
    @admin_role.update!(permissions: { "read" => true, "write" => true, "delete" => true })

    @application.assign_role_to_user!(@user, "admin", source: 'oidc')

    # Get token and check for role permissions
    post oauth_authorize_path, params: {
      client_id: @application.client_id,
      response_type: "code",
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    follow_redirect!
    post oauth_consent_path, params: {
      consent: "approve",
      client_id: @application.client_id,
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    authorization_code = extract_code_from_redirect(response.location)

    post oauth_token_path, params: {
      grant_type: "authorization_code",
      code: authorization_code,
      redirect_uri: "https://example.com/callback",
      client_id: @application.client_id,
      client_secret: @test_client_secret
    }

    token_response = JSON.parse(response.body)
    id_token = token_response["id_token"]
    decoded_token = JWT.decode(id_token, nil, false).first

    assert decoded_token["role_permissions"].present?
    role_permissions = decoded_token["role_permissions"].find { |rp| rp["name"] == "admin" }
    assert_equal({ "read" => true, "write" => true, "delete" => true }, role_permissions["permissions"])
  end

  test "should use custom role claim name" do
    @application.update!(role_claim_name: "user_roles")
    @application.assign_role_to_user!(@user, "admin", source: 'oidc')

    # Get token
    post oauth_authorize_path, params: {
      client_id: @application.client_id,
      response_type: "code",
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    follow_redirect!
    post oauth_consent_path, params: {
      consent: "approve",
      client_id: @application.client_id,
      redirect_uri: "https://example.com/callback",
      scope: "openid profile email",
      state: "test-state"
    }

    authorization_code = extract_code_from_redirect(response.location)

    post oauth_token_path, params: {
      grant_type: "authorization_code",
      code: authorization_code,
      redirect_uri: "https://example.com/callback",
      client_id: @application.client_id,
      client_secret: @test_client_secret
    }

    token_response = JSON.parse(response.body)
    id_token = token_response["id_token"]
    decoded_token = JWT.decode(id_token, nil, false).first

    assert_nil decoded_token["roles"]
    assert_includes decoded_token["user_roles"], "admin"
  end

  private

  def extract_code_from_redirect(redirect_url)
    uri = URI.parse(redirect_url)
    query_params = CGI.parse(uri.query)
    query_params["code"]&.first
  end
end