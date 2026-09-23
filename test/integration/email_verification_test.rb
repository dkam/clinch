require "test_helper"

# CLN-07: `email_verified` must mean something. Relying parties link and
# provision accounts on a verified address, so Clinch may only assert it once
# the address has proven it receives mail — and a self-service change must not
# take effect until the new address has done so.
class EmailVerificationTest < ActionDispatch::IntegrationTest
  include ActionMailer::TestHelper

  setup do
    @alice = users(:alice)
    @app = applications(:kavita_app)
    ActionMailer::Base.deliveries.clear
  end

  # --- Self-service change ----------------------------------------------------

  test "changing your email holds the new address until it is confirmed" do
    sign_in_as(@alice)

    perform_enqueued_jobs do
      patch profile_path, params: {user: {email_address: "alice-new@example.com", current_password: "password"}}
    end

    assert_redirected_to profile_path
    @alice.reload
    assert_equal "alice@example.com", @alice.email_address, "the address must not change before confirmation"
    assert_equal "alice-new@example.com", @alice.unconfirmed_email

    mail = ActionMailer::Base.deliveries.last
    assert_equal ["alice-new@example.com"], mail.to
    assert confirmation_path_in(mail), "the mail to the new address must carry a confirmation link"
  end

  test "following the confirmation link switches the address, marks it verified and tells both addresses" do
    sign_in_as(@alice)
    path = request_change_and_capture_link("alice-new@example.com")

    get path
    assert_response :success

    ActionMailer::Base.deliveries.clear
    perform_enqueued_jobs { patch path }

    assert_redirected_to profile_path
    @alice.reload
    assert_equal "alice-new@example.com", @alice.email_address
    assert_nil @alice.unconfirmed_email
    assert @alice.email_verified?

    recipients = ActionMailer::Base.deliveries.flat_map(&:to)
    assert_includes recipients, "alice@example.com"
    assert_includes recipients, "alice-new@example.com"
  end

  test "the confirmation link works without a signed-in session" do
    sign_in_as(@alice)
    path = request_change_and_capture_link("alice-new@example.com")
    sign_out

    patch path

    assert_equal "alice-new@example.com", @alice.reload.email_address
  end

  test "a wrong password stages nothing and sends nothing" do
    sign_in_as(@alice)

    assert_no_enqueued_emails do
      patch profile_path, params: {user: {email_address: "alice-new@example.com", current_password: "wrong"}}
    end

    assert_nil @alice.reload.unconfirmed_email
  end

  test "an address another account holds is refused before anything is sent" do
    sign_in_as(@alice)

    assert_no_enqueued_emails do
      patch profile_path, params: {user: {email_address: users(:bob).email_address, current_password: "password"}}
    end

    assert_response :unprocessable_entity
    assert_nil @alice.reload.unconfirmed_email
  end

  test "a newer change request invalidates the older link" do
    sign_in_as(@alice)
    first = request_change_and_capture_link("alice-first@example.com")
    request_change_and_capture_link("alice-second@example.com")

    patch first

    @alice.reload
    assert_equal "alice@example.com", @alice.email_address
    assert_equal "alice-second@example.com", @alice.unconfirmed_email
  end

  test "a link is spent once it has been used" do
    sign_in_as(@alice)
    path = request_change_and_capture_link("alice-new@example.com")
    patch path
    @alice.update!(email_address: "alice-admin-set@example.com")

    patch path

    assert_equal "alice-admin-set@example.com", @alice.reload.email_address
  end

  test "confirmation is refused if the address was taken in the meantime" do
    sign_in_as(@alice)
    path = request_change_and_capture_link("taken@example.com")
    User.create!(email_address: "taken@example.com", password: "password123")

    patch path

    assert_equal "alice@example.com", @alice.reload.email_address
  end

  # --- Where the verified state comes from ------------------------------------

  test "an admin changing someone's address leaves it unverified and asks the new address to confirm" do
    sign_in_as(users(:two)) # in admin_group via fixtures

    perform_enqueued_jobs do
      patch admin_user_path(@alice), params: {user: {email_address: "alice-by-admin@example.com"}}
    end

    @alice.reload
    assert_equal "alice-by-admin@example.com", @alice.email_address
    refute @alice.email_verified?

    to_new = ActionMailer::Base.deliveries.select { |m| m.to == ["alice-by-admin@example.com"] }
    assert to_new.any? { |m| confirmation_path_in(m) }, "the new address must be sent a confirmation link"
  end

  test "an unverified user can ask for a link to verify their current address" do
    @alice.update_column(:email_verified_at, nil)
    sign_in_as(@alice)

    perform_enqueued_jobs { post email_confirmations_path }

    mail = ActionMailer::Base.deliveries.last
    assert_equal ["alice@example.com"], mail.to
    patch confirmation_path_in(mail)

    assert @alice.reload.email_verified?
  end

  test "accepting an invitation verifies the address it was sent to" do
    invitee = User.create!(email_address: "invitee@example.com", password: "password123", status: :pending_invitation)
    refute invitee.email_verified?

    put invitation_path(invitee.generate_token_for(:invitation_login)),
      params: {password: "newpassword123", password_confirmation: "newpassword123"}

    assert invitee.reload.email_verified?
  end

  test "the first account, signed up with any address, starts unverified" do
    # Signup is only open while there are no accounts at all.
    ActiveRecord::Base.connection.disable_referential_integrity { User.delete_all }

    post signup_path, params: {user: {email_address: "first@example.com", password: "password123", password_confirmation: "password123"}}

    refute User.find_by(email_address: "first@example.com").email_verified?
  end

  # --- What relying parties are told ------------------------------------------

  test "an unverified address is reported as unverified in the ID token and userinfo" do
    @alice.update_column(:email_verified_at, nil)

    id_token = OidcJwtService.generate_id_token(@alice, @app, scopes: "openid email")
    payload = JWT.decode(id_token, nil, false).first
    assert_equal false, payload["email_verified"]

    token = OidcAccessToken.create!(application: @app, user: @alice, scope: "openid email")
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_equal false, JSON.parse(response.body)["email_verified"]
  end

  test "a verified address is reported as verified" do
    id_token = OidcJwtService.generate_id_token(@alice, @app, scopes: "openid email")
    assert_equal true, JWT.decode(id_token, nil, false).first["email_verified"]
  end

  private

  def request_change_and_capture_link(new_email)
    ActionMailer::Base.deliveries.clear
    perform_enqueued_jobs do
      patch profile_path, params: {user: {email_address: new_email, current_password: "password"}}
    end
    mail = ActionMailer::Base.deliveries.find { |m| m.to == [new_email] }
    assert mail, "expected a confirmation mail to #{new_email}"
    confirmation_path_in(mail)
  end

  def confirmation_path_in(mail)
    body = mail.text_part&.decoded || mail.body.decoded
    body[%r{/email_confirmations/[^\s"<]+}]
  end
end
