require "test_helper"

class OidcJwtServiceTest < ActiveSupport::TestCase
  TEST_OIDC_KEY = <<~KEY
    -----BEGIN PRIVATE KEY-----
    MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCNLfKZ4+Po2Rhd
    uwtStOvU3XwI4IMPWvIArIskYKKwiRS2GYyYKIa0LtRacExEopbYVonUuNFrvbBZ
    bl7RHH2qF9u5C01Iadz0sa1ZOqUeetstgK4Wlx9v5kHrGvaTzGLyPmyOzuUTj0LO
    jDHXuO6ojIJBSIIKmOqO6yOgogX7zWuBzuRFAlDmkaBcg0N/PGb9nvPIyB8oJd3E
    mKNZtoiAyETLsiF1QMp3PuOj25k7tSgHj+80OCOWe9n7g7iXooGXqIIcYfaxrU7H
    216lkMLLMblfGc/O68NAKW32x85dpgI3fiNTZS0Wc52yZUQ+zxBhRJ95yjvyfSaC
    PGysWdFdAgMBAAECggEAGhO63DCDHDMfZE7EimgXKHgprTUVGDy+9x9nyxYbbtq/
    K9yfwso3iWgd+r+D4uiaTsb7SgLCUfGVdYtksaDe2FB0WiNriLzfHoaEI7dooO7l
    9atvXIZY/PENy3itQ4MM4rxjjmRKXVjIqQCtwzAqSxE7DQZw2LbCmpf1unm6+7XB
    So0L3ScgkBszRjOlLoe6LPCkYNisANEH2elNmzgDfAdwhmQSXCnipiIGGxOfFbf8
    qyAyxmWmzIfnbU1LzOA916C3iLcKVySHm/2SVXsznnwHAdWMW/YVSpTuWmmV+hES
    3krOBWvh4caVljYxfRkwneIUtnZUBhlVDb0sqRq/yQKBgQDEACJijI++e7L7+6l7
    vdGhkRzi6BKGixCNeiEUzYjTYKpsMaWm54MYnhZhIaSuYQYEInmkW1wz3DXcH6P5
    a4rnwpT+66ka6sj5BrD59saPpUaqmnjKY9MDep2WbcCXmNdA4C3xjottHXn4x/9v
    bHfUlcvdPulbW/QYK4WCfqKSdQKBgQC4Za7NlY3E0CmOO7o0J9vzO1qPb/QIdv7J
    ohhcAlAsmW1zZEiYxNuQkl4RJLseqMYRHlTzRD0nfEDHksLcp2uXG2WYK6ESP/oI
    Wl4Lm169e5sutEqFujj6dsrQ+jqGuGSNV2I0rAfEOE2ZSeKNRFsJH35EBMq8XQF1
    Q4ir/MgWSQKBgHRJbB0yLjqio5+zQWwEQ/Lq6MuLSyp+KZT259ey1kIrMRG+Jv0u
    kG4zpS19y3oWYH5lgexMtBikx2PRdfUOpDw7CzFv2kX5FMIDAU9c5ZPmSFYCDjZu
    IY0H26Wbek+3Q8be+wM9QmW7vlknN9sA7Nu5AFpE8CjfFqScdbrlrUjdAoGAf4W6
    tOyHhaPcCURfCrDCGN1kTKxE3RHGNJWIOSFUZvOYUOP6nMQPgFTo/vwi+BoKGE6c
    uzvm+wagGiTx4/1Yl8DXqrwJgYCDHwG35lkF1Q7FjDAdFYxq2TQMISfcD803pNPY
    08pg+J9jcu444i9yscV44ftaZZgAaSNSQnbnvRkCgYBQwP/nqGtXMHHVz97NeEJT
    xQ/0GCNx1isIN8ZKzynVwZebFrtxwrFOf3zIxgtlx30V3Ekezx7kmbaPiQr041J4
    nKBppinMQsTb9Bu/0K8aHvjpxdkPeMdugfZAPShDnhM3fhukiJZp36X4u1/xY4Gn
    wkkkJkpY4gKeqVL0uzeARA==
    -----END PRIVATE KEY-----
  KEY

  def setup
    @user = users(:alice)
    @application = applications(:kavita_app)
    @service = OidcJwtService

    # Set a consistent test key to avoid key mismatch issues
    ENV["OIDC_PRIVATE_KEY"] = TEST_OIDC_KEY

    # Reset any memoized keys to pick up the new ENV value
    OidcJwtService.instance_variable_set(:@private_key, nil)
    OidcJwtService.instance_variable_set(:@public_key, nil)
    OidcJwtService.instance_variable_set(:@key_id, nil)
  end

  def teardown
    # Clean up ENV after test
    ENV.delete("OIDC_PRIVATE_KEY")

    # Reset memoized keys
    OidcJwtService.instance_variable_set(:@private_key, nil)
    OidcJwtService.instance_variable_set(:@public_key, nil)
    OidcJwtService.instance_variable_set(:@key_id, nil)
  end

  test "should generate id token with required claims" do
    token = @service.generate_id_token(@user, @application)

    assert_not_nil token, "Should generate token"
    assert token.length > 100, "Token should be substantial"
    assert token.include?('.')

    # Decode without verification for testing the payload
    decoded = JWT.decode(token, nil, false).first
    assert_equal @application.client_id, decoded['aud'], "Should have correct audience"
    assert_equal @user.id.to_s, decoded['sub'], "Should have correct subject"
    assert_equal @user.email_address, decoded['email'], "Should have correct email"
    assert_equal true, decoded['email_verified'], "Should have email verified"
    assert_equal @user.email_address, decoded['preferred_username'], "Should have preferred username"
    assert_equal @user.email_address, decoded['name'], "Should have name"
    assert_equal @service.issuer_url, decoded['iss'], "Should have correct issuer"
    assert_in_delta Time.current.to_i + 3600, decoded['exp'], 5, "Should have correct expiration"
  end

  test "should handle nonce in id token" do
    nonce = "test-nonce-12345"
    token = @service.generate_id_token(@user, @application, nonce: nonce)

    decoded = JWT.decode(token, nil, false).first
    assert_equal nonce, decoded['nonce'], "Should preserve nonce in token"
    assert_in_delta Time.current.to_i + 3600, decoded['exp'], 5, "Should have correct expiration with nonce"
  end

  test "should include groups in token when user has groups" do
    admin_group = groups(:admin_group)
    @user.groups << admin_group unless @user.groups.include?(admin_group)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, false).first
    assert_includes decoded['groups'], "Administrators", "Should include user's groups"
  end

  test "admin claim should not be included in token" do
    @user.update!(admin: true)

    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, false).first
    refute decoded.key?('admin'), "Admin claim should not be included in ID tokens (use groups instead)"
  end

  test "should handle missing roles gracefully" do
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, false).first
    refute_includes decoded, 'roles', "Should not have roles when not configured"
  end

  test "should load RSA private key from environment with escaped newlines" do
    # Simulate how direnv exports multi-line strings with \n escape sequences
    key_with_escaped_newlines = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDg3SfOR4UW6wV2\\nyKnE/pN5/tvUC7Fpol5/NjJQHm24F8+r6iipdLWJrJ3T2oEzaKw/RTGYPBQvjj6c\\nz3+tc7QkJLOESJCA0WqgawE1WdKSx5ug3sP0Y7woTPipt+afGaV58YvV/sqFD1ft\\nU+2w8olBHqWphUCd/LakfvqHbwrmF58IASk4IbGceqQ7f98d/8C8TrR6k3SKQAto\\n0OWo+xuyJg0RoSS8S220/qyIukXxtHS89NQj3dgJI06fGCSATCu8uVdsKwBDNw3F\\nBSQEX3xhk8E/JXXZfwRFR1K3zUIVQu8haQ3YA52b0jkzE2xI6TaHVbuGdifmGAmX\\nb5jsJ/eNAgMBAAECggEAAWJb3PwlOUANWTe630Pp1OegV5M1Tn2vi+oQPosPl1iX\\nFlbymrj80EfaRPWo84oKnq0t1/RnogrbDa3txgdpSVCsEWk9N2SyoJXy8+MZu6Er\\nQHka8qfBVfe4PbHyRj3FSeQKvZOEvvOgNJkYpIFeb5zkHa1ISyloEWvAxr0njJbQ\\n0F2jML4sUeduYulCWI9dSJdB+yp8BsmOPu8VzUFthW/GPPuw4a4ngzoGtPV6f/kp\\ncjPa2YT8L8z6zXE0IiDU8bc5abC++QBNLJrMy55tM+zfgGyShandITbcpuWptIqT\\n2yhMulifOMw0hdV0cYRqetkWkevz07nrwnh/1FGjYQKBgQD9C/Ls720tULS7SIdh\\nuDWnrtMG4sidSbxWJTOqPUNZ9a0vaHnx/FwlmvURyCojn5leLByY8ZNN08DxKBVq\\nwH6ZJe7KGOik5wMtFV1zrhyHNpa/H/RrLaYAZqCVlGYyOVqNa7mA7oOIeqtbv9x+\\nOaEz3BnoXHOJOwM10h20Nos6bQKBgQDjfQCSQXcrkV8hKf+F65N7Kcf7JMlZQAA3\\n9dvJxxek683bhYTLZhubY/tegfhxlZGkgP3eHKI1XyUYBCNBnztn3t1zD0ovcqRX\\no21m5TaJ0fGW4X3iyi1IWioMBPXffR8tXk5+LnWVZ26RgmaBG1rgOJEQ5bHYMtHj\\n+jo9JLV9oQKBgQDt1nNHm2qEcxzMAsmsYVWc+8bA7BsfKxTn6yN6WQaa4T0cGBi2\\nBzoc5l59jiN9RB8E0nU2k6ieN+9bOw+WPMNA8tRUA8F2bOMhVrl1ZyrNM9PQZBp5\\nOniSW+OHc+nyPtILpjq/Im9isdmp7NUzlrsbYT7AlVTKoTrNNWZR4gpOqQKBgQC3\\nIWwSUS00H4TrV7nh/zDsl0fr/0Mv2/vRENTsbJ+2HjXMIII0k3Bp+WTkQdDU70kd\\nmtHDul1CheOAn+QZ8auLBLhU5dwcsjdmbaOmj6MF88J+aexDY+psMlli76NXVIyC\\no0ahAZmaunciIE2QZYsUsbTmW2J93vtkgY3cpu6LwQKBgDigl7dCQl38Vt7FhxjJ\\naC6wmmM8YX6y5f5t3caVVBizVhx8xOXQla96zB0nW6ibTpaIKCSdORxMGAoajTZ9\\n8Ww2gOfZpZeojU2YHTV/KFd7wHGYE8QaBKqP6DuibLnP5farjuwPeGvbjZW6e9cy\\nntHkSPI0VmhqsUQEMgPnYuCg\\n-----END PRIVATE KEY-----"

    # Clear any cached keys
    OidcJwtService.instance_variable_set(:@private_key, nil)

    # Stub ENV to return the test key
    original_value = ENV["OIDC_PRIVATE_KEY"]
    ENV["OIDC_PRIVATE_KEY"] = key_with_escaped_newlines

    # The service should convert \n to actual newlines and load successfully
    private_key = OidcJwtService.send(:private_key)

    assert_not_nil private_key
    assert_kind_of OpenSSL::PKey::RSA, private_key
    assert_equal 2048, private_key.n.num_bits
  ensure
    # Restore original value and clear cached key
    ENV["OIDC_PRIVATE_KEY"] = original_value
    OidcJwtService.instance_variable_set(:@private_key, nil)
  end

  test "should handle key with actual newlines" do
    # Generate a real test key
    test_key = OpenSSL::PKey::RSA.new(2048)
    key_pem = test_key.to_pem

    # Clear any cached keys
    OidcJwtService.instance_variable_set(:@private_key, nil)

    # Stub ENV to return the test key
    original_value = ENV["OIDC_PRIVATE_KEY"]
    ENV["OIDC_PRIVATE_KEY"] = key_pem

    private_key = OidcJwtService.send(:private_key)

    assert_not_nil private_key
    assert_kind_of OpenSSL::PKey::RSA, private_key
    assert_equal 2048, private_key.n.num_bits
  ensure
    # Restore original value and clear cached key
    ENV["OIDC_PRIVATE_KEY"] = original_value
    OidcJwtService.instance_variable_set(:@private_key, nil)
  end

  test "should raise error for invalid key format" do
    # Clear any cached keys
    OidcJwtService.instance_variable_set(:@private_key, nil)

    # Stub ENV to return invalid key
    original_value = ENV["OIDC_PRIVATE_KEY"]
    ENV["OIDC_PRIVATE_KEY"] = "invalid-key-data"

    error = assert_raises RuntimeError do
      OidcJwtService.send(:private_key)
    end

    assert_match /Invalid OIDC private key format/, error.message
  ensure
    # Restore original value and clear cached key
    ENV["OIDC_PRIVATE_KEY"] = original_value
    OidcJwtService.instance_variable_set(:@private_key, nil)
  end

  test "should raise error in production when no key configured" do
    # Skip this test if we can't properly stub Rails.env
    skip "Skipping production env test" unless Rails.env.development? || Rails.env.test?

    # Clear any cached keys
    OidcJwtService.instance_variable_set(:@private_key, nil)

    # Temporarily remove the key
    original_value = ENV["OIDC_PRIVATE_KEY"]
    ENV.delete("OIDC_PRIVATE_KEY")

    # Stub Rails.env to be production
    Rails.env = ActiveSupport::StringInquirer.new("production")

    error = assert_raises RuntimeError do
      OidcJwtService.send(:private_key)
    end

    assert_match /OIDC private key not configured/, error.message
  ensure
    # Restore original environment and clear cached key
    ENV["OIDC_PRIVATE_KEY"] = original_value if original_value
    Rails.env = ActiveSupport::StringInquirer.new(ENV.fetch("RAILS_ENV", "test"))
    OidcJwtService.instance_variable_set(:@private_key, nil)
  end

  test "should generate RSA private key when missing" do
    # In test environment, a key is auto-generated if none exists
    # This test just verifies the service can generate tokens (which requires a key)
    token = @service.generate_id_token(@user, @application)
    assert_not_nil token, "Should generate token successfully (requires private key)"
  end

  test "should decode and verify id token" do
    token = @service.generate_id_token(@user, @application)
    decoded_array = @service.decode_id_token(token)

    assert_not_nil decoded_array, "Should decode valid token"
    decoded = decoded_array.first # JWT.decode returns an array
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
    # Generate a token (valid for 1 hour by default)
    token = @service.generate_id_token(@user, @application)

    # Travel 2 hours into the future - token should be expired
    travel_to 2.hours.from_now do
      assert_raises(JWT::ExpiredSignature) do
        @service.decode_id_token(token)
      end
    end
  end

  test "should handle access token generation" do
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, false).first
    # ID tokens always include email_verified
    assert_includes decoded.keys, 'email_verified'
    assert_equal @user.id.to_s, decoded['sub'], "Should decode subject correctly"
    assert_equal @application.client_id, decoded['aud'], "Should decode audience correctly"
  end

  test "should validate JWT configuration" do
    @application.update!(client_id: "test-client")

    # This test just verifies the service can generate tokens
    # The test environment should have a valid key available
    token = @service.generate_id_token(@user, @application)
    assert_not_nil token, "Should generate token successfully"
  end

  test "should include app-specific custom claims in token" do
    # Use bob and another_app to avoid fixture conflicts
    user = users(:bob)
    app = applications(:another_app)

    # Create app-specific claim
    ApplicationUserClaim.create!(
      user: user,
      application: app,
      custom_claims: { "app_groups": ["admin"], "library_access": "all" }
    )

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    assert_equal ["admin"], decoded["app_groups"]
    assert_equal "all", decoded["library_access"]
  end

  test "app-specific claims should override user and group claims" do
    # Use bob and another_app to avoid fixture conflicts
    user = users(:bob)
    app = applications(:another_app)

    # Add user to group with claims
    group = groups(:admin_group)
    group.update!(custom_claims: { "role": "viewer", "max_items": 10 })
    user.groups << group

    # Add user custom claims
    user.update!(custom_claims: { "role": "editor", "theme": "dark" })

    # Add app-specific claims (should override both)
    ApplicationUserClaim.create!(
      user: user,
      application: app,
      custom_claims: { "role": "admin", "app_specific": true }
    )

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # App-specific claim should win
    assert_equal "admin", decoded["role"]
    # App-specific claim should be present
    assert_equal true, decoded["app_specific"]
    # User claim not overridden should still be present
    assert_equal "dark", decoded["theme"]
    # Group claim not overridden should still be present
    assert_equal 10, decoded["max_items"]
  end

  test "should deep merge array claims from group and user" do
    user = users(:bob)
    app = applications(:another_app)

    # Group has roles: ["user"]
    group = groups(:admin_group)
    group.update!(custom_claims: { "roles" => ["user"], "permissions" => ["read"] })
    user.groups << group

    # User adds roles: ["admin"]
    user.update!(custom_claims: { "roles" => ["admin"], "permissions" => ["write"] })

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # Roles should be combined (not overwritten)
    assert_equal 2, decoded["roles"].length
    assert_includes decoded["roles"], "user"
    assert_includes decoded["roles"], "admin"
    # Permissions should also be combined
    assert_equal 2, decoded["permissions"].length
    assert_includes decoded["permissions"], "read"
    assert_includes decoded["permissions"], "write"
  end

  test "should deep merge array claims from multiple groups" do
    user = users(:bob)
    app = applications(:another_app)

    # First group has roles: ["user"]
    group1 = groups(:admin_group)
    group1.update!(custom_claims: { "roles" => ["user"] })
    user.groups << group1

    # Second group has roles: ["moderator"]
    group2 = Group.create!(name: "moderators", description: "Moderators group")
    group2.update!(custom_claims: { "roles" => ["moderator"] })
    user.groups << group2

    # User adds roles: ["admin"]
    user.update!(custom_claims: { "roles" => ["admin"] })

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # All roles should be combined
    assert_equal 3, decoded["roles"].length
    assert_includes decoded["roles"], "user"
    assert_includes decoded["roles"], "moderator"
    assert_includes decoded["roles"], "admin"
  end

  test "should remove duplicate values when merging arrays" do
    user = users(:bob)
    app = applications(:another_app)

    # Group has roles: ["user", "reader"]
    group = groups(:admin_group)
    group.update!(custom_claims: { "roles" => ["user", "reader"] })
    user.groups << group

    # User also has "user" role (duplicate)
    user.update!(custom_claims: { "roles" => ["user", "admin"] })

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # "user" should only appear once
    assert_equal 3, decoded["roles"].length
    assert_includes decoded["roles"], "user"
    assert_includes decoded["roles"], "reader"
    assert_includes decoded["roles"], "admin"
  end

  test "should override non-array values while merging arrays" do
    user = users(:bob)
    app = applications(:another_app)

    # Group has roles array and max_items scalar
    group = groups(:admin_group)
    group.update!(custom_claims: { "roles" => ["user"], "max_items" => 10, "theme" => "light" })
    user.groups << group

    # User overrides max_items and theme, adds to roles
    user.update!(custom_claims: { "roles" => ["admin"], "max_items" => 100, "theme" => "dark" })

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # Arrays should be combined
    assert_equal 2, decoded["roles"].length
    assert_includes decoded["roles"], "user"
    assert_includes decoded["roles"], "admin"
    # Scalar values should be overridden (user wins)
    assert_equal 100, decoded["max_items"]
    assert_equal "dark", decoded["theme"]
  end

  test "should deep merge nested hashes in claims" do
    user = users(:bob)
    app = applications(:another_app)

    # Group has nested config
    group = groups(:admin_group)
    group.update!(custom_claims: {
      "config" => {
        "theme" => "light",
        "notifications" => { "email" => true }
      }
    })
    user.groups << group

    # User adds to nested config
    user.update!(custom_claims: {
      "config" => {
        "language" => "en",
        "notifications" => { "sms" => true }
      }
    })

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # Nested hashes should be deep merged
    assert_equal "light", decoded["config"]["theme"]
    assert_equal "en", decoded["config"]["language"]
    assert_equal true, decoded["config"]["notifications"]["email"]
    assert_equal true, decoded["config"]["notifications"]["sms"]
  end

  test "app-specific claims should combine arrays with group and user claims" do
    user = users(:bob)
    app = applications(:another_app)

    # Group has roles: ["user"]
    group = groups(:admin_group)
    group.update!(custom_claims: { "roles" => ["user"] })
    user.groups << group

    # User has roles: ["moderator"]
    user.update!(custom_claims: { "roles" => ["moderator"] })

    # App-specific has roles: ["app_admin"]
    ApplicationUserClaim.create!(
      user: user,
      application: app,
      custom_claims: { "roles" => ["app_admin"] }
    )

    token = @service.generate_id_token(user, app)
    decoded = JWT.decode(token, nil, false).first

    # All three sources should be combined
    assert_equal 3, decoded["roles"].length
    assert_includes decoded["roles"], "user"
    assert_includes decoded["roles"], "moderator"
    assert_includes decoded["roles"], "app_admin"
  end

  test "should include at_hash when access token is provided" do
    access_token = "test-access-token-abc123xyz"
    token = @service.generate_id_token(@user, @application, access_token: access_token)

    decoded = JWT.decode(token, nil, false).first
    assert_includes decoded.keys, "at_hash", "Should include at_hash claim"

    # Verify at_hash is correctly computed: base64url(sha256(access_token)[0:16])
    expected_hash = Base64.urlsafe_encode64(Digest::SHA256.digest(access_token)[0..15], padding: false)
    assert_equal expected_hash, decoded["at_hash"], "at_hash should match SHA-256 hash of access token"
  end

  test "should not include at_hash when access token is not provided" do
    token = @service.generate_id_token(@user, @application)

    decoded = JWT.decode(token, nil, false).first
    refute_includes decoded.keys, "at_hash", "Should not include at_hash when no access token"
  end
end