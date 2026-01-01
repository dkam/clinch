require "test_helper"

class OidcAuthorizationCodeTest < ActiveSupport::TestCase
  def setup
    @auth_code = oidc_authorization_codes(:one)
  end

  test "should be valid with all required attributes" do
    assert @auth_code.valid?
  end

  test "should belong to an application" do
    assert_respond_to @auth_code, :application
    assert_equal applications(:kavita_app), @auth_code.application
  end

  test "should belong to a user" do
    assert_respond_to @auth_code, :user
    assert_equal users(:alice), @auth_code.user
  end

  test "should generate code before validation on create" do
    new_code = OidcAuthorizationCode.new(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback"
    )
    assert_nil new_code.code_hmac
    assert new_code.save
    assert_not_nil new_code.code_hmac
    assert_match(/^[a-f0-9]{64}$/, new_code.code_hmac) # SHA256 hex digest
  end

  test "should set expiry before validation on create" do
    new_code = OidcAuthorizationCode.new(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback"
    )
    assert_nil new_code.expires_at
    assert new_code.save
    assert_not_nil new_code.expires_at
    assert new_code.expires_at > Time.current
    assert new_code.expires_at <= 11.minutes.from_now # Allow some variance
  end

  test "should validate presence of code_hmac" do
    @auth_code.code_hmac = nil
    assert_not @auth_code.valid?
    assert_includes @auth_code.errors[:code_hmac], "can't be blank"
  end

  test "should validate uniqueness of code_hmac" do
    @auth_code.save! if @auth_code.changed?
    duplicate = OidcAuthorizationCode.new(
      code_hmac: @auth_code.code_hmac,
      application: applications(:another_app),
      user: users(:bob),
      redirect_uri: "https://example.com/callback"
    )
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:code_hmac], "has already been taken"
  end

  test "should validate presence of redirect_uri" do
    @auth_code.redirect_uri = nil
    assert_not @auth_code.valid?
    assert_includes @auth_code.errors[:redirect_uri], "can't be blank"
  end

  test "should identify expired codes correctly" do
    @auth_code.expires_at = 5.minutes.ago
    assert @auth_code.expired?, "Should identify past expiry as expired"

    @auth_code.expires_at = 5.minutes.from_now
    assert_not @auth_code.expired?, "Should identify future expiry as not expired"

    @auth_code.expires_at = Time.current
    assert @auth_code.expired?, "Should identify current time as expired"
  end

  test "should identify usable codes correctly" do
    # Fresh, unused code should be usable
    @auth_code.expires_at = 5.minutes.from_now
    @auth_code.used = false
    assert @auth_code.usable?, "Fresh unused code should be usable"

    # Used code should not be usable
    @auth_code.used = true
    assert_not @auth_code.usable?, "Used code should not be usable"

    # Expired code should not be usable
    @auth_code.used = false
    @auth_code.expires_at = 5.minutes.ago
    assert_not @auth_code.usable?, "Expired code should not be usable"

    # Used and expired code should not be usable
    @auth_code.used = true
    @auth_code.expires_at = 5.minutes.ago
    assert_not @auth_code.usable?, "Used and expired code should not be usable"
  end

  test "should consume code correctly" do
    @auth_code.used = false
    assert_not @auth_code.used?, "Code should initially be unused"

    @auth_code.consume!
    @auth_code.reload
    assert @auth_code.used?, "Code should be marked as used after consumption"
  end

  test "valid scope should return only unused and non-expired codes" do
    # Create codes with different states
    valid_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback"
    )

    used_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback",
      used: true
    )

    expired_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback",
      expires_at: 5.minutes.ago
    )

    valid_codes = OidcAuthorizationCode.valid
    assert_includes valid_codes, valid_code
    assert_not_includes valid_codes, used_code
    assert_not_includes valid_codes, expired_code
  end

  test "expired scope should return only expired codes" do
    # Create codes with different expiry states
    non_expired_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback",
      expires_at: 5.minutes.from_now
    )

    expired_code = OidcAuthorizationCode.create!(
      application: applications(:kavita_app),
      user: users(:alice),
      redirect_uri: "https://example.com/callback",
      expires_at: 5.minutes.ago
    )

    expired_codes = OidcAuthorizationCode.expired
    assert_includes expired_codes, expired_code
    assert_not_includes expired_codes, non_expired_code
  end

  test "should handle concurrent consumption safely" do
    @auth_code.used = false
    @auth_code.save!

    # Simulate concurrent consumption
    original_used = @auth_code.used?
    @auth_code.consume!

    assert_not original_used, "Code should be unused before consumption"
    assert @auth_code.used?, "Code should be used after consumption"
  end

  test "should generate secure random codes" do
    codes = []
    5.times do
      code = OidcAuthorizationCode.create!(
        application: applications(:kavita_app),
        user: users(:alice),
        redirect_uri: "https://example.com/callback"
      )
      codes << code.code_hmac
    end

    # All codes should be unique
    assert_equal codes.length, codes.uniq.length

    # All codes should be SHA256 hex digests
    codes.each do |code|
      assert_match(/^[a-f0-9]{64}$/, code)
      assert_equal 64, code.length # SHA256 hex digest
    end
  end
end
