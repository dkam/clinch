require "test_helper"

class OidcDeviceCodeTest < ActiveSupport::TestCase
  def setup
    @application = Application.create!(
      name: "Device Code Model Test",
      slug: "device-code-model-test",
      app_type: "oidc",
      is_public_client: true,
      active: true
    )
    @user = User.create!(email_address: "device_model@example.com", password: "password123")
  end

  test "generates an opaque device_code stored as HMAC and looked up by plaintext" do
    dc = OidcDeviceCode.create!(application: @application)

    assert dc.plaintext_device_code.present?
    assert dc.device_code_hmac.present?
    assert_not_equal dc.plaintext_device_code, dc.device_code_hmac
    assert_equal dc, OidcDeviceCode.find_by_plaintext_device_code(dc.plaintext_device_code)
    assert_nil OidcDeviceCode.find_by_plaintext_device_code("wrong")
  end

  test "generates a short user_code from the unambiguous alphabet" do
    dc = OidcDeviceCode.create!(application: @application)

    assert_equal 8, dc.user_code.length
    # No visually ambiguous characters (0/O, 1/I) and only the allowed alphabet.
    assert_match(/\A[A-HJ-NP-Z2-9]{8}\z/, dc.user_code)
  end

  test "find_by_user_code normalizes case, hyphens, and whitespace" do
    dc = OidcDeviceCode.create!(application: @application)
    formatted = "#{dc.user_code[0, 4]}-#{dc.user_code[4, 4]}".downcase

    assert_equal dc, OidcDeviceCode.find_by_user_code(formatted)
    assert_equal dc, OidcDeviceCode.find_by_user_code(" #{dc.user_code} ")
    assert_nil OidcDeviceCode.find_by_user_code("nope")
  end

  test "regenerates the user_code when generation collides with an existing code" do
    existing = OidcDeviceCode.create!(application: @application)
    taken = existing.user_code
    fresh = "ABCDEFGH" # in-alphabet, effectively guaranteed != the random `taken`

    # First candidate collides with the existing code, the second is unique — the
    # generator must retry rather than surface a uniqueness error.
    candidates = [taken, fresh].each
    dc = OidcDeviceCode.new(application: @application)
    dc.define_singleton_method(:random_user_code) { candidates.next }
    dc.save!

    assert_equal fresh, dc.user_code
    assert_not_equal taken, dc.user_code
  end

  test "starts pending and approve! attaches the user and auth context" do
    dc = OidcDeviceCode.create!(application: @application)
    assert dc.pending?

    dc.approve!(user: @user, acr: "1", auth_time: 1_700_000_000)

    assert dc.approved?
    assert_equal @user, dc.user
    assert_equal "1", dc.acr
    assert_equal 1_700_000_000, dc.auth_time
  end

  test "deny! marks the code denied" do
    dc = OidcDeviceCode.create!(application: @application)
    dc.deny!
    assert dc.denied?
  end

  test "expired? reflects expires_at" do
    assert OidcDeviceCode.create!(application: @application, expires_at: 1.minute.ago).expired?
    assert_not OidcDeviceCode.create!(application: @application).expired?
  end

  test "uses_pkce? and rejects malformed code_challenge" do
    assert_not OidcDeviceCode.create!(application: @application).uses_pkce?

    valid_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    dc = OidcDeviceCode.create!(application: @application, code_challenge: valid_challenge, code_challenge_method: "S256")
    assert dc.uses_pkce?

    bad = OidcDeviceCode.new(application: @application, code_challenge: "too-short")
    assert_not bad.valid?
    assert_includes bad.errors[:code_challenge], "must be 43-128 characters of base64url encoding"
  end
end
