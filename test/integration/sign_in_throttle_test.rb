require "test_helper"
require "minitest/mock"

# CLN-03: the sign-in rate limits key on IP only, so an attacker holding a
# phished password can rotate addresses and keep guessing — at the password
# step, and at the TOTP step, whose pending state never expired. These pin a
# per-account limit on both steps and an expiry on the pending state.
class SignInThrottleTest < ActionDispatch::IntegrationTest
  setup do
    # Rails.cache is a :null_store in test; the per-account counters need a real one.
    @original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    @alice = users(:alice)
  end

  teardown do
    Rails.cache = @original_cache
  end

  # --- Password step ----------------------------------------------------------

  test "failed passwords from many addresses lock the account's password step" do
    10.times { |i| sign_in_with("wrong", ip: "203.0.113.#{i}") }

    sign_in_with("password", ip: "198.51.100.1")

    assert_redirected_to signin_path
    assert_nil Session.find_by(user: @alice), "the correct password must be refused while the account is throttled"
  end

  test "the lock lifts when the window passes" do
    10.times { |i| sign_in_with("wrong", ip: "203.0.113.#{i}") }

    travel 61.minutes do
      sign_in_with("password")
      assert Session.exists?(user: @alice)
    end
  end

  test "a successful sign-in clears the count" do
    9.times { sign_in_with("wrong") }
    sign_in_with("password")
    Session.where(user: @alice).delete_all

    9.times { sign_in_with("wrong") }
    sign_in_with("password")

    assert Session.exists?(user: @alice)
  end

  test "an address with no account is throttled with the same answer, so it reveals nothing" do
    11.times { post signin_path, params: {email_address: "nobody@example.com", password: "wrong"} }
    for_nobody = flash[:alert]

    11.times { sign_in_with("wrong") }

    assert_match(/Too many failed attempts/, for_nobody)
    assert_equal for_nobody, flash[:alert]
  end

  # --- TOTP step --------------------------------------------------------------

  test "failed codes lock the TOTP step, even across fresh password sign-ins" do
    @alice.enable_totp!
    sign_in_with("password")
    3.times { post totp_verification_path, params: {code: "000000"} }
    sign_in_with("password") # a fresh pending state must not mean a fresh budget
    2.times { post totp_verification_path, params: {code: "000000"} }

    post totp_verification_path, params: {code: @alice.reload.console_totp}

    assert_nil Session.find_by(user: @alice), "the correct code must be refused while the account is throttled"
  end

  test "a correct code within the budget still signs in" do
    @alice.enable_totp!
    sign_in_with("password")
    4.times { post totp_verification_path, params: {code: "000000"} }

    post totp_verification_path, params: {code: @alice.reload.console_totp}

    assert Session.exists?(user: @alice)
  end

  test "the TOTP step expires if the code is not entered promptly" do
    @alice.enable_totp!
    sign_in_with("password")

    travel 6.minutes do
      post totp_verification_path, params: {code: @alice.reload.console_totp}

      assert_redirected_to signin_path
      assert_nil Session.find_by(user: @alice)
    end
  end

  test "loading the TOTP page does not spend the per-IP attempt budget" do
    @alice.enable_totp!
    sign_in_with("password")
    store = SessionsController.cache_store
    increments = 0

    store.stub(:increment, ->(*) { increments += 1 }) do
      get totp_verification_path
    end

    assert_response :success
    assert_equal 0, increments
  end

  # --- Passkey step -----------------------------------------------------------

  test "a passkey challenge expires if it is not answered promptly" do
    @alice.webauthn_credentials.create!(
      external_id: Base64.urlsafe_encode64("cred-1"), public_key: Base64.urlsafe_encode64("pk"),
      sign_count: 0, nickname: "Key"
    )
    post "/sessions/webauthn/challenge", params: {email: @alice.email_address}
    assert_response :success

    travel 6.minutes do
      post "/sessions/webauthn/verify", params: {credential: {id: "x"}}

      assert_equal "Session expired. Please try again.", JSON.parse(response.body)["error"]
    end
  end

  private

  def sign_in_with(password, ip: "127.0.0.1")
    post signin_path, params: {email_address: @alice.email_address, password: password}, env: {"REMOTE_ADDR" => ip}
  end
end
