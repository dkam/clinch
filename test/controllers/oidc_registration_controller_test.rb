require "test_helper"

class OidcRegistrationControllerTest < ActionDispatch::IntegrationTest
  JSON_HEADERS = {"Content-Type" => "application/json"}.freeze

  def teardown
    Setting.where(key: Application::DCR_SETTING_KEY).delete_all
    Application.where("slug LIKE ?", "%-%").where(metadata: nil).delete_all
    Application.where("metadata LIKE ?", "%dynamically_registered%").destroy_all
  end

  def enable_dcr
    Setting.set(Application::DCR_SETTING_KEY, true)
  end

  def register(body)
    post "/oauth/register", params: body.to_json, headers: JSON_HEADERS
  end

  test "registration is disabled by default" do
    register(redirect_uris: ["https://client.example.com/cb"], token_endpoint_auth_method: "none")
    assert_response :forbidden
    assert_equal "access_denied", JSON.parse(@response.body)["error"]
  end

  test "registers a public client and returns no secret" do
    enable_dcr
    register(
      redirect_uris: ["https://client.example.com/cb"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      client_name: "My MCP Connector"
    )

    assert_response :created
    body = JSON.parse(@response.body)
    assert body["client_id"].present?
    assert_not body.key?("client_secret")
    assert_equal ["https://client.example.com/cb"], body["redirect_uris"]
    assert_equal "none", body["token_endpoint_auth_method"]

    app = Application.find_by(client_id: body["client_id"])
    assert app.public_client?
    assert app.require_pkce?
    assert_empty app.allowed_groups, "a freshly registered client must be default-deny"
  end

  test "registers a confidential client and returns a secret once" do
    enable_dcr
    register(
      redirect_uris: ["https://client.example.com/cb"],
      token_endpoint_auth_method: "client_secret_basic"
    )

    assert_response :created
    body = JSON.parse(@response.body)
    assert body["client_secret"].present?
    assert_equal 0, body["client_secret_expires_at"]

    app = Application.find_by(client_id: body["client_id"])
    assert app.confidential_client?
    assert app.authenticate_client_secret(body["client_secret"])
  end

  test "requires at least one redirect_uri" do
    enable_dcr
    register(token_endpoint_auth_method: "none")
    assert_response :bad_request
    assert_equal "invalid_redirect_uri", JSON.parse(@response.body)["error"]
  end

  test "rejects non-loopback http redirect_uris" do
    enable_dcr
    register(redirect_uris: ["http://evil.example.com/cb"], token_endpoint_auth_method: "none")
    assert_response :bad_request
    assert_equal "invalid_redirect_uri", JSON.parse(@response.body)["error"]
  end

  test "allows http redirect_uris for loopback" do
    enable_dcr
    register(redirect_uris: ["http://localhost:8123/cb"], token_endpoint_auth_method: "none")
    assert_response :created
  end

  test "rejects unsupported grant types" do
    enable_dcr
    register(redirect_uris: ["https://client.example.com/cb"], grant_types: ["client_credentials"])
    assert_response :bad_request
    assert_equal "invalid_client_metadata", JSON.parse(@response.body)["error"]
  end

  test "registers a client requesting the device_code grant advertised in discovery" do
    enable_dcr
    register(
      redirect_uris: ["https://client.example.com/cb"],
      token_endpoint_auth_method: "none",
      grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]
    )
    assert_response :created
    assert_includes JSON.parse(@response.body)["grant_types"], "urn:ietf:params:oauth:grant-type:device_code"
  end

  test "registration accepts exactly the grant types discovery advertises" do
    get "/.well-known/openid-configuration"
    advertised = JSON.parse(@response.body)["grant_types_supported"]
    # Single source of truth: what we advertise is what registration accepts.
    assert_equal OidcController::SUPPORTED_GRANT_TYPES, advertised
    assert_includes advertised, "urn:ietf:params:oauth:grant-type:device_code"
  end

  test "rejects a non-JSON body" do
    enable_dcr
    post "/oauth/register", params: "not json", headers: JSON_HEADERS
    assert_response :bad_request
    assert_equal "invalid_client_metadata", JSON.parse(@response.body)["error"]
  end

  # --- Discovery advertisement ----------------------------------------------

  test "discovery advertises registration_endpoint only when enabled" do
    get "/.well-known/openid-configuration"
    assert_not JSON.parse(@response.body).key?("registration_endpoint")

    enable_dcr
    get "/.well-known/openid-configuration"
    assert JSON.parse(@response.body)["registration_endpoint"].end_with?("/oauth/register")
  end

  test "RFC 8414 metadata alias mirrors OIDC discovery" do
    get "/.well-known/oauth-authorization-server"
    assert_response :success
    config = JSON.parse(@response.body)
    assert config["token_endpoint"].end_with?("/oauth/token")
    assert config["authorization_endpoint"].end_with?("/oauth/authorize")
  end

  # --- Admin runtime toggle --------------------------------------------------

  test "admin can toggle the registration window at runtime" do
    sign_in_as(users(:alice)) # alice is in the admin group

    patch "/admin/dynamic_client_registration", params: {enabled: "true"}
    assert_redirected_to admin_applications_path
    assert Application.dynamic_registration_enabled?

    patch "/admin/dynamic_client_registration", params: {enabled: "false"}
    assert_not Application.dynamic_registration_enabled?
  end

  test "non-admins cannot toggle registration" do
    sign_in_as(users(:one)) # not an admin
    patch "/admin/dynamic_client_registration", params: {enabled: "true"}
    assert_redirected_to root_path
    assert_not Application.dynamic_registration_enabled?
  end
end
