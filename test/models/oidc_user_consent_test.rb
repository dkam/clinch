require "test_helper"

class OidcUserConsentTest < ActiveSupport::TestCase
  def setup
    @consent = oidc_user_consents(:alice_consent)
  end

  test "should be valid with all required attributes" do
    assert @consent.valid?
  end

  test "should belong to a user" do
    assert_respond_to @consent, :user
    assert_equal users(:alice), @consent.user
  end

  test "should belong to an application" do
    assert_respond_to @consent, :application
    assert_equal applications(:kavita_app), @consent.application
  end

  test "should validate presence of user" do
    @consent.user = nil
    assert_not @consent.valid?
    assert_includes @consent.errors[:user], "can't be blank"
  end

  test "should validate presence of application" do
    @consent.application = nil
    assert_not @consent.valid?
    assert_includes @consent.errors[:application], "can't be blank"
  end

  test "should validate presence of scopes_granted" do
    @consent.scopes_granted = nil
    assert_not @consent.valid?
    assert_includes @consent.errors[:scopes_granted], "can't be blank"
  end

  test "should validate presence of granted_at" do
    @consent.granted_at = nil
    assert_not @consent.valid?
    assert_includes @consent.errors[:granted_at], "can't be blank"
  end

  test "should validate uniqueness of user_id scoped to application_id" do
    # Should be able to create consent for different user with same app
    new_consent = OidcUserConsent.new(
      user: users(:bob),
      application: @consent.application,
      scopes_granted: "openid email"
    )
    assert new_consent.valid?

    # Should NOT be able to create consent for same user with same app
    duplicate_consent = OidcUserConsent.new(
      user: @consent.user,
      application: @consent.application,
      scopes_granted: "openid profile"
    )
    assert_not duplicate_consent.valid?
    assert_includes duplicate_consent.errors[:user_id], "has already been taken"
  end

  test "should set granted_at before validation on create" do
    new_consent = OidcUserConsent.new(
      user: users(:alice),
      application: applications(:another_app),
      scopes_granted: "openid email"
    )
    assert_nil new_consent.granted_at
    assert new_consent.save!, "Should save successfully"
    assert_not_nil new_consent.granted_at
    assert new_consent.granted_at.is_a?(Time), "granted_at should be a Time object"
  end

  test "scopes should parse space-separated scopes into array" do
    @consent.scopes_granted = "openid profile email groups"
    assert_equal ["openid", "profile", "email", "groups"], @consent.scopes

    # Handle single scope
    @consent.scopes_granted = "openid"
    assert_equal ["openid"], @consent.scopes

    # Handle empty string
    @consent.scopes_granted = ""
    assert_equal [], @consent.scopes

    # Handle extra spaces
    @consent.scopes_granted = "openid  profile   email"
    assert_equal ["openid", "profile", "email"], @consent.scopes
  end

  test "scopes= should join array into space-separated string" do
    @consent.scopes = ["openid", "profile", "email"]
    assert_equal "openid profile email", @consent.scopes_granted

    # Handle single item array
    @consent.scopes = ["openid"]
    assert_equal "openid", @consent.scopes_granted

    # Handle empty array
    @consent.scopes = []
    assert_equal "", @consent.scopes_granted

    # Handle duplicates
    @consent.scopes = ["openid", "profile", "openid"]
    assert_equal "openid profile", @consent.scopes_granted
  end

  test "should handle string input for scopes=" do
    @consent.scopes = "openid profile"
    assert_equal "openid profile", @consent.scopes_granted
    assert_equal ["openid", "profile"], @consent.scopes
  end

  test "covers_scopes? should correctly identify scope coverage" do
    @consent.scopes_granted = "openid profile email groups"

    # Should cover when all requested scopes are granted
    assert @consent.covers_scopes?(["openid"]), "Should cover single requested scope"
    assert @consent.covers_scopes?(["openid", "profile"]), "Should cover multiple requested scopes"
    assert @consent.covers_scopes?(["email", "groups"]), "Should cover different combination"
    assert @consent.covers_scopes?(["openid", "profile", "email", "groups"]), "Should cover all granted scopes"

    # Should not cover when requested includes non-granted scope
    assert_not @consent.covers_scopes?(["admin"]), "Should not cover non-granted scope"
    assert_not @consent.covers_scopes?(["openid", "admin"]), "Should not cover mixed granted/non-granted"
    assert_not @consent.covers_scopes?(["admin", "write"]), "Should not cover all non-granted"

    # Handle string input
    assert @consent.covers_scopes?("openid"), "Should handle string input"
    assert_not @consent.covers_scopes?("admin"), "Should handle string input for non-granted scope"

    # Handle empty requested scopes
    assert @consent.covers_scopes?([]), "Should cover empty array"
    assert @consent.covers_scopes?(nil), "Should handle nil input"
  end

  test "covers_scopes? should handle edge cases" do
    # Consent with no scopes
    @consent.scopes_granted = ""
    assert_not @consent.covers_scopes?(["openid"]), "Should not cover any scope when no scopes granted"
    assert @consent.covers_scopes?([]), "Should cover empty request when no scopes granted"

    # Consent with one scope
    @consent.scopes_granted = "openid"
    assert @consent.covers_scopes?(["openid"]), "Should cover matching single scope"
    assert_not @consent.covers_scopes?(["profile"]), "Should not cover different single scope"
  end

  test "formatted_scopes should provide human-readable scope names" do
    @consent.scopes_granted = "openid profile email groups"
    expected = "Basic authentication, Profile information, Email address, Group membership"
    assert_equal expected, @consent.formatted_scopes

    # Test single scope
    @consent.scopes_granted = "openid"
    assert_equal "Basic authentication", @consent.formatted_scopes

    # Test unknown scope
    @consent.scopes_granted = "unknown_scope"
    assert_equal "Unknown scope", @consent.formatted_scopes

    # Test mixed known and unknown
    @consent.scopes_granted = "openid custom_scope"
    assert_equal "Basic authentication, Custom scope", @consent.formatted_scopes

    # Test empty scopes
    @consent.scopes_granted = ""
    assert_equal "", @consent.formatted_scopes
  end

  test "should maintain consistency between scopes getter and setter" do
    original_scopes = ["openid", "profile", "email"]
    @consent.scopes = original_scopes
    assert_equal original_scopes, @consent.scopes

    # Modify scopes
    new_scopes = ["openid", "groups"]
    @consent.scopes = new_scopes
    assert_equal new_scopes, @consent.scopes
  end

  test "should handle consent updates correctly" do
    # Use a different user and app combination to avoid uniqueness constraint
    consent = OidcUserConsent.create!(
      user: users(:alice),
      application: applications(:another_app), # Different app than in fixtures
      scopes_granted: "openid email"
    )

    # Update to include more scopes
    consent.scopes = ["openid", "email", "profile"]
    consent.save!

    consent.reload
    assert_equal ["openid", "email", "profile"], consent.scopes
    assert_equal "openid email profile", consent.scopes_granted

    # Should still cover original scopes
    assert consent.covers_scopes?(["openid", "email"])
    # Should cover new scopes
    assert consent.covers_scopes?(["profile"])
    # Should cover all scopes
    assert consent.covers_scopes?(["openid", "email", "profile"])
  end

  test "should validate scope coverage logic with real OIDC scenarios" do
    # Typical OIDC consent scenario
    @consent.scopes_granted = "openid profile email"

    # Application requests only openid (required for OIDC)
    assert @consent.covers_scopes?(["openid"]), "Should cover required openid scope"

    # Application requests standard scopes
    assert @consent.covers_scopes?(["openid", "profile"]), "Should cover standard OIDC scopes"

    # Application requests more than granted
    assert_not @consent.covers_scopes?(["openid", "profile", "groups"]),
      "Should not cover scopes not granted"

    # Application requests subset
    assert @consent.covers_scopes?(["email"]), "Should cover subset of granted scopes"
  end
end
