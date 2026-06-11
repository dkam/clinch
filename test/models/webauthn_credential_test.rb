require "test_helper"

class WebauthnCredentialTest < ActiveSupport::TestCase
  # suspicious_sign_count?(new_sign_count) — clone detection per WebAuthn §6.1.1.
  # Build an in-memory credential with a given stored sign_count; no persistence
  # needed since the method only reads self.sign_count.
  def credential(stored:)
    WebauthnCredential.new(sign_count: stored)
  end

  test "does not flag when the authenticator reports no counter (synced passkeys)" do
    # Both 0 -> authenticator doesn't implement a counter; must NOT be suspicious.
    refute credential(stored: 0).suspicious_sign_count?(0)
    # Stored 0, first real use.
    refute credential(stored: 0).suspicious_sign_count?(5)
    # Stored non-zero but authenticator now reports 0 -> no counter, not a clone.
    refute credential(stored: 5).suspicious_sign_count?(0)
  end

  test "does not flag a normal increasing counter" do
    refute credential(stored: 5).suspicious_sign_count?(6)
    refute credential(stored: 1).suspicious_sign_count?(1000)
  end

  test "flags a non-advancing counter as a possible clone" do
    assert credential(stored: 5).suspicious_sign_count?(5), "equal count is suspicious"
    assert credential(stored: 5).suspicious_sign_count?(3), "decreasing count is suspicious"
  end
end
