require "test_helper"

class OidcJwtServiceTest < ActiveSupport::TestCase
  def setup
    @user = users(:alice)
    @application = applications(:kavita_app)
    @service = OidcJwtService
  end

  test "should generate id token with required claims" do
    token = @service.generate_id_token(@user, @application)

    assert_not_nil token, "Should generate token"
    assert token.length > 100, "Token should be substantial"
    assert token.include?('.')

    decoded = JWT.decode(token, nil, true)
    assert_equal @application.client_id, decoded['aud'], "Should have correct audience"
    assert_equal @user.id.to_s, decoded['sub'], "Should have correct subject"
    assert_equal @user.email_address, decoded['email'], "Should have correct email"
    assert_equal true, decoded['email_verified'], "Should have email verified"
    assert_equal @user.email_address, decoded['preferred_username'], "Should have preferred username"
    assert_equal @user.email_address, decoded['name'], "Should have name"
    assert_equal "https://localhost:3000", decoded['iss'], "Should have correct issuer"
    assert_equal Time.now.to_i + 3600, decoded['exp'], "Should have correct expiration"
  end

  test "should handle nonce in id token" do
    nonce = "test-nonce-12345"
    token = @service.generate_id_token(@user, @application, nonce: nonce)

    decoded = JWT.decode(token, nil, true)
    assert_equal nonce, decoded['nonce'], "Should preserve nonce in token"
    assert_equal Time.now.to_i + 3600, decoded['exp'], "Should have correct expiration with nonce"
  end

  test "should include groups in token when user has groups" do
    @user.groups << groups(:admin_group)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_includes decoded['groups'], "admin", "Should include user's groups"
  end

  test "should include admin claim for admin users" do
    @user.update!(admin: true)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_equal true, decoded['admin'], "Admin users should have admin claim"
  end

  test "should handle role-based claims when enabled" do
    @application.update!(
      role_mapping_enabled: true,
      role_mapping_mode: "oidc_managed",
      role_claim_name: "roles"
    )

    @application.assign_role_to_user!(@user, "editor", source: 'oidc', metadata: { synced_at: Time.current })

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_includes decoded['roles'], "editor", "Should include user's role"
  end

  test "should include role metadata when configured" do
    @application.update!(
      role_mapping_enabled: true,
      role_mapping_mode: "oidc_managed",
      parsed_managed_permissions: {
        "include_permissions" => true,
        "include_metadata" => true
      }
    )

    role = @application.application_roles.create!(
      name: "editor",
      display_name: "Content Editor",
      permissions: ["read", "write"]
    )

    @application.assign_role_to_user!(
      @user,
      "editor",
      source: 'oidc',
      metadata: {
        synced_at: Time.current,
        department: "Content Team",
        level: "2"
      }
    )

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_equal "Content Editor", decoded['role_display_name'], "Should include role display name"
    assert_includes decoded['role_permissions'], "read", "Should include read permission"
    assert_includes decoded['role_permissions'], "write", "Should include write permission"
    assert_equal "Content Team", decoded['role_department'], "Should include department"
    assert_equal "2", decoded['role_level'], "Should include level"
  end

  test "should handle missing roles gracefully" do
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    refute_includes decoded, 'roles', "Should not have roles when not configured"
  end

  test "should use RSA private key from environment" do
    ENV.stub(:fetch, "OIDC_PRIVATE_KEY") { "test-private-key" }

    private_key = @service.private_key
    assert_equal "test-private-key", private_key.to_s, "Should use private key from environment"
  end

  test "should generate RSA private key when missing" do
    ENV.stub(:fetch, nil) { nil }
    ENV.stub(:fetch, "OIDC_PRIVATE_KEY", nil) { nil }
    Rails.application.credentials.stub(:oidc_private_key, nil) { nil }

    private_key = @service.private_key
    assert_not_nil private_key, "Should generate private key when missing"
    assert private_key.is_a?(OpenSSL::PKey::RSA), "Should generate RSA private key"
    assert_equal 2048, private_key.num_bits, "Should generate 2048-bit key"
  end

  test "should get corresponding public key" do
    public_key = @service.public_key
    assert_not_nil public_key, "Should have public key"
    assert_equal "RSA", public_key.kty, "Should be RSA key"
    assert_equal 256, public_key.n, "Should be 256-bit key"
  end

  test "should decode and verify id token" do
    token = @service.generate_id_token(@user, @application)
    decoded = @service.decode_id_token(token)

    assert_not_nil decoded, "Should decode valid token"
    assert_equal @user.id.to_s, decoded['sub'], "Should decode subject correctly"
    assert_equal @application.client_id, decoded['aud'], "Should decode audience correctly"
    assert decoded['exp'] > Time.current.to_i, "Token should not be expired"
  end

  test "should reject invalid id tokens" do
    invalid_tokens = [
      "invalid.token",
      "header.payload.signature",
      "eyJ0",
      nil,
      "Bearer"
    ]

    invalid_tokens.each do |invalid_token|
      assert_raises(JWT::DecodeError) do
        @service.decode_id_token(invalid_token)
      end
    end
  end

  test "should handle expired tokens" do
    travel_to 2.hours.from_now do
      token = @service.generate_id_token(@user, @application, exp: 1.hour.from_now)
      travel_back

      assert_raises(JWT::ExpiredSignature) do
        @service.decode_id_token(token)
      end
    end
  end

  test "should handle access token generation" do
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    refute_includes decoded.keys, 'email_verified'
    assert_equal @user.id.to_s, decoded['sub'], "Should decode subject correctly"
    assert_equal @application.client_id, decoded['aud'], "Should decode audience correctly"
  end

  test "should handle JWT errors gracefully" do
    original_algorithm = OpenSSL::PKey::RSA::DEFAULT_PRIVATE_KEY

    OpenSSL::PKey::RSA.stub(:new, -> { raise "Key generation failed" }) do
      OpenSSL::PKey::RSA.new(2048)
    end

    assert_raises(RuntimeError, message: /Key generation failed/) do
      @service.private_key
    end

    OpenSSL::PKey::RSA.stub(:new, original_algorithm) do
      restored_key = @service.private_key
      assert_not_equal original_algorithm, restored_key, "Should restore after error"
    end
  end

  test "should validate JWT configuration" do
    @application.update!(client_id: "test-client")

    error = assert_raises(StandardError, message: /no key found/) do
      @service.generate_id_token(@user, @application)
    end
    assert_match /no key found/, error.message, "Should warn about missing private key"
  end
  end
end