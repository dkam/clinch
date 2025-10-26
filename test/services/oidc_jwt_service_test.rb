require "test_helper"

class OidcJwtServiceTest < ActiveSupport::TestCase
  def setup
    @user = users(:alice)
    @application = applications(:kavita_app)
    @service = OidcJwtService
  end

  test "should generate id token with required claims" do
    # Test JWT generation with basic user
    token = @service.generate_id_token(@user, @application)

    assert_not_nil token, "Should generate token"
    assert token.length > 100, "Token should be substantial"
    assert token.include?('.'), "Token should have segments"

    # Decode and verify payload
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
    # Test nonce handling
    nonce = "test-nonce-12345"
    token = @service.generate_id_token(@user, @application, nonce: nonce)

    decoded = JWT.decode(token, nil, true)
    assert_equal nonce, decoded['nonce'], "Should preserve nonce in token"
    assert_equal Time.now.to_i + 3600, decoded['exp'], "Should have correct expiration with nonce"
  end

  test "should include groups in token when user has groups" do
    # Test group inclusion
    @user.groups << groups(:admin_group)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_includes decoded['groups'], "admin", "Should include user's groups"
  end

  test "should include admin claim for admin users" do
    # Test admin claim
    @user.update!(admin: true)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_equal true, decoded['admin'], "Admin users should have admin claim"
  end

  test "should handle role-based claims when enabled" do
    # Test role-based claims
    @application.update!(
      role_mapping_enabled: true,
      role_mapping_mode: "oidc_managed",
      role_claim_name: "roles"
    )

    # Assign role to user
    @application.assign_role_to_user!(@user, "editor", source: 'oidc', metadata: { synced_at: Time.current })

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_includes decoded['roles'], "editor", "Should include user's role"
  end

  test "should include role metadata when configured" do
    # Test role metadata inclusion
    @application.update!(
      role_mapping_enabled: true,
      role_mapping_mode: "oidc_managed",
      parsed_managed_permissions: {
        "include_permissions" => true,
        "include_metadata" => true
      }
    )

    # Assign role with metadata
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

  test "should handle hybrid role mapping mode" do
    # Test hybrid mode (combining OIDC roles with local groups)
    @application.update!(
      role_mapping_mode: "hybrid",
      role_mapping_enabled: true,
      role_prefix: "ext-"
    )

    # Create external role and local group
    external_role = @application.application_roles.create!(name: "ext-admin")
    @user.groups << groups(:admin_group)

    token = @service.generate_id_token(@user, @application)
    decoded = JWT.decode(token, nil, true)

    # User should be allowed (has external role OR admin group)
    assert_includes decoded['roles'], "ext-admin", "Should include external role"
    assert_includes decoded['groups'], "admin", "Should include admin group"
  end

  test "should handle missing roles gracefully" do
    # Test when roles claim is missing or empty
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    assert_not_includes decoded, 'roles', "Should not have roles key when not configured"
  end

  test "should use RSA private key from environment" do
    # Test private key handling
    ENV.stub(:fetch, "OIDC_PRIVATE_KEY") { "test-private-key" }

    private_key = @service.private_key
    assert_equal "test-private-key", private_key.to_s, "Should use private key from environment"
  end

  test "should generate RSA private key when missing" do
    # Test private key generation in development
    ENV.stub(:fetch, nil) { nil }
    ENV.stub(:fetch, "OIDC_PRIVATE_KEY", nil) { nil }
    Rails.application.credentials.stub(:oidc_private_key, nil) { nil }

    private_key = @service.private_key
    assert_not_nil private_key, "Should generate private key when missing"
    assert private_key.is_a?(OpenSSL::PKey::RSA), "Should generate RSA private key"
    assert_equal 2048, private_key.num_bits, "Should generate 2048-bit key"
  end

  test "should get corresponding public key" do
    # Test public key retrieval
    public_key = @service.public_key
    assert_not_nil public_key, "Should have public key"
    assert_equal "RSA", public_key.kty, "Should be RSA key"
    assert_equal 256, public_key.n, "Should be 256-bit key"
  end

  test "should generate JWKS format" do
    # Test JWKS generation
    jwks = @service.jwks
    assert_not_nil jwks, "Should generate JWKS"
    assert jwks.is_a?(Hash), "JWKS should be a hash"
    assert_includes jwks, :keys, "JWKS should contain keys array"
    assert_equal 1, jwks[:keys].size, "JWKS should contain one key"

    key_data = jwks[:keys].first
    assert_equal "RSA", key_data[:kty], "Key should be RSA"
    assert key_data[:kid], "Key should have kid"
    assert key_data[:use], "sig", "Key should be for signing"
    assert_equal "RS256", key_data[:alg], "Key should use RS256 algorithm"
  end

  test "should decode and verify id token" do
    # Test token verification
    token = @service.generate_id_token(@user, @application)
    decoded = @service.decode_id_token(token)

    assert_not_nil decoded, "Should decode valid token"
    assert_equal @user.id.to_s, decoded['sub'], "Should decode subject correctly"
    assert_equal @application.client_id, decoded['aud'], "Should decode audience correctly"
    assert decoded['exp'] > Time.current.to_i, "Token should not be expired"
  end

  test "should reject invalid id tokens" do
    # Test token validation
    invalid_tokens = [
      "invalid.token",
      "header.payload.signature",  # Missing signature
      "eyJ0",  # Too short
      nil, # Empty token
      "Bearer"  # Bearer prefix (should be raw JWT)
    ]

    invalid_tokens.each do |invalid_token|
      assert_raises(JWT::DecodeError) do
        @service.decode_id_token(invalid_token)
      end, "Should raise error for invalid token: #{invalid_token}"
    end
  end

  test "should handle expired tokens" do
    # Test expired token handling
    travel_to 2.hours.from_now do
      token = @service.generate_id_token(@user, @application, exp: 1.hour.from_now)
      travel_back

      assert_raises(JWT::ExpiredSignature) do
        @service.decode_id_token(token)
      end, "Should raise error for expired token"
    end
  end
  end

  test "should handle access token generation" do
    # Test access token (simpler than ID token)
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, true)
    # Access tokens typically don't have email_verified claim
    refute_includes decoded.keys, 'email_verified'
    # But should still have standard claims
    assert_equal @user.id.to_s, decoded['sub'], "Should have subject"
    assert_equal @application.client_id, decoded['aud'], "Should have audience"
  end

  test "should handle JWT errors gracefully" do
    # Test error handling
    original_algorithm = OpenSSL::PKey::RSA::DEFAULT_PRIVATE_KEY

    # Temporarily break the service
    OpenSSL::PKey::RSA.stub(:new, -> { raise "Key generation failed" }) do
      OpenSSL::PKey::RSA.new(2048)
    end

    assert_raises(RuntimeError, message: /Key generation failed/) do
      @service.private_key
    end

    # Restore original
    OpenSSL::PKey::RSA.stub(:new, original_algorithm) do
      restored_key = @service.private_key
      assert_not_equal original_algorithm, restored_key, "Should restore after error"
    end
  end

  test "should validate JWT configuration" do
    # Test service configuration validation
    @application.update!(client_id: "test-client")

    error = assert_raises(StandardError) do
      @service.generate_id_token(@user, @application)
    end

    assert_match /no key found/, error.message, "Should warn about missing key"
  end

  test "should handle key rotation scenarios" do
    # Test key rotation (development scenario)
    old_key = @service.public_key

    # Generate new key
    @service.instance_variable_set(:@public_key, nil)
    @service.instance_variable_set(:@key_id, nil)
    new_public_key = @service.public_key

    assert_not_equal old_key, new_public_key, "Should generate new public key"
    assert_not_equal old_key.to_pem, new_public_key.to_pem, "New key should be different"

    # Key ID should have changed
    new_key_id = @service.key_id
    assert_not_nil new_key_id, "Should generate new key ID"
    assert_match /^\w{16}$/, new_key_id, "Key ID should be base64url format"
  end
end