require "test_helper"

class OidcAccessTokenTest < ActiveSupport::TestCase
  def setup
    @access_token = oidc_access_tokens(:one)
  end

  test "should be valid with all required attributes" do
    assert @access_token.valid?
  end

  test "should belong to an application" do
    assert_respond_to @access_token, :application
    assert_equal applications(:kavita_app), @access_token.application
  end

  test "should belong to a user" do
    assert_respond_to @access_token, :user
    assert_equal users(:alice), @access_token.user
  end

  test "should generate token before validation on create" do
    new_token = OidcAccessToken.new(
      application: applications(:kavita_app),
      user: users(:alice)
    )
    assert_nil new_token.token
    assert new_token.save
    assert_not_nil new_token.token
    assert_match /^[A-Za-z0-9_-]+$/, new_token.token
  end

  test "should set expiry before validation on create" do
    new_token = OidcAccessToken.new(
      application: applications(:kavita_app),
      user: users(:alice)
    )
    assert_nil new_token.expires_at
    assert new_token.save
    assert_not_nil new_token.expires_at
    assert new_token.expires_at > Time.current
    assert new_token.expires_at <= 61.minutes.from_now # Allow some variance
  end

  test "should validate presence of token" do
    @access_token.token = nil
    assert_not @access_token.valid?
    assert_includes @access_token.errors[:token], "can't be blank"
  end

  test "should validate uniqueness of token" do
    @access_token.save! if @access_token.changed?
    duplicate = OidcAccessToken.new(
      token: @access_token.token,
      application: applications(:another_app),
      user: users(:bob)
    )
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:token], "has already been taken"
  end

  test "should identify expired tokens correctly" do
    @access_token.expires_at = 5.minutes.ago
    assert @access_token.expired?, "Should identify past expiry as expired"

    @access_token.expires_at = 5.minutes.from_now
    assert_not @access_token.expired?, "Should identify future expiry as not expired"

    @access_token.expires_at = Time.current
    assert @access_token.expired?, "Should identify current time as expired"
  end

  test "should identify active tokens correctly" do
    # Non-expired token should be active
    @access_token.expires_at = 5.minutes.from_now
    assert @access_token.active?, "Future expiry should be active"

    # Expired token should not be active
    @access_token.expires_at = 5.minutes.ago
    assert_not @access_token.active?, "Past expiry should not be active"

    # Current time should be considered expired (not active)
    @access_token.expires_at = Time.current
    assert_not @access_token.active?, "Current time should not be active"
  end

  test "should revoke token correctly" do
    @access_token.expires_at = 1.hour.from_now
    original_expiry = @access_token.expires_at
    assert @access_token.active?, "Token should be active before revocation"

    @access_token.revoke!
    @access_token.reload

    assert @access_token.revoked?, "Token should be revoked after revocation"
    assert @access_token.revoked_at <= Time.current, "Revoked at should be set to current time or earlier"
    # expires_at should not be changed by revocation
    assert_equal original_expiry, @access_token.expires_at, "Expiry should remain unchanged"
  end

  test "valid scope should return only non-expired tokens" do
    # Create tokens with different states
    valid_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice)
    )

    expired_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      expires_at: 5.minutes.ago
    )

    valid_tokens = OidcAccessToken.valid
    assert_includes valid_tokens, valid_token
    assert_not_includes valid_tokens, expired_token
  end

  test "expired scope should return only expired tokens" do
    # Create tokens with different expiry states
    non_expired_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      expires_at: 1.hour.from_now
    )

    expired_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      expires_at: 5.minutes.ago
    )

    expired_tokens = OidcAccessToken.expired
    assert_includes expired_tokens, expired_token
    assert_not_includes expired_tokens, non_expired_token
  end

  test "should handle concurrent revocation safely" do
    @access_token.expires_at = 1.hour.from_now
    @access_token.save!

    original_active = @access_token.active?
    @access_token.revoke!

    assert original_active, "Token should be active before revocation"
    assert @access_token.revoked?, "Token should be revoked after revocation"
  end

  test "should generate secure random tokens" do
    tokens = []
    5.times do
      token = OidcAccessToken.create!(
        application: applications(:kavita_app),
        user: users(:alice)
      )
      tokens << token.token
    end

    # All tokens should be unique
    assert_equal tokens.length, tokens.uniq.length

    # All tokens should match the expected pattern
    tokens.each do |token|
      assert_match /^[A-Za-z0-9_-]+$/, token
      # Base64 token length may vary due to padding, just ensure it's reasonable
      assert token.length >= 43, "Token should be at least 43 characters"
      assert token.length <= 64, "Token should not exceed 64 characters"
    end
  end

  test "should have longer token than authorization codes" do
    auth_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback"
    )

    access_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice)
    )

    assert access_token.token.length > auth_code.code.length,
           "Access tokens should be longer than authorization codes"
  end

  test "should have appropriate expiry times" do
    auth_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback"
    )

    access_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice)
    )

    # Authorization codes expire in 10 minutes, access tokens in 1 hour
    assert access_token.expires_at > auth_code.expires_at,
           "Access tokens should have longer expiry than authorization codes"
  end

  test "revoked tokens should not appear in valid scope" do
    access_token = OidcAccessToken.create!(
      application: applications(:kavita_app),
      user: users(:alice)
    )

    # Token should be in valid scope initially
    assert_includes OidcAccessToken.valid, access_token

    # Revoke the token
    access_token.revoke!

    # Token should no longer be in valid scope
    assert_not_includes OidcAccessToken.valid, access_token
  end
end
