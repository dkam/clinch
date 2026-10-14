require "test_helper"
require "minitest/mock"

# OIDC Back-Channel Logout 1.0: when a user's session at an RP has to end, the
# OP POSTs a signed logout token to the RP, naming the user (sub) and the
# session (sid) the RP saw in its ID token.
class BackchannelLogoutTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "backchannel_user@example.com", password: "password123")
    @application = Application.create!(
      name: "Backchannel App",
      slug: "backchannel-app",
      app_type: "oidc",
      redirect_uris: ["https://rp.example.com/callback"].to_json,
      backchannel_logout_uri: "https://rp.example.com/backchannel-logout",
      active: true
    )
    grant_everyone_access(@application)
  end

  test "revoking consent sends the RP a logout token it can match to its session" do
    consent = OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])
    id_token = JWT.decode(OidcJwtService.generate_id_token(@user, @application, consent: consent), nil, false).first
    sign_in_as(@user)

    delete revoke_consent_active_sessions_path, params: {application_id: @application.id}
    tokens = logout_tokens_posted

    assert_equal 1, tokens.size
    payload, header = tokens.first
    assert_equal id_token["sid"], payload["sid"]
    assert_equal id_token["sub"], payload["sub"]
    assert_equal @application.client_id, payload["aud"]
    assert payload["exp"] > payload["iat"], "logout tokens must expire"
    assert_equal "logout+jwt", header["typ"]
    assert_not payload.key?("nonce")
  end

  test "an ID token names the session that logout tokens refer to" do
    consent = OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])

    id_token = JWT.decode(OidcJwtService.generate_id_token(@user, @application, consent: consent), nil, false).first

    assert_equal consent.sid, id_token["sid"]
  end

  test "disabling a user logs them out of their apps" do
    OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])

    @user.update!(status: :disabled)

    assert_equal 1, logout_tokens_posted.size
  end

  test "deleting a user logs them out of their apps" do
    OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])

    @user.destroy!

    assert_equal 1, logout_tokens_posted.size
  end

  test "deleting an application logs its users out of it" do
    OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])

    @application.destroy!

    assert_equal 1, logout_tokens_posted.size
  end

  test "a logout the RP times out on is retried" do
    OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])
    sign_in_as(@user)
    delete signout_path

    job_data = enqueued_jobs.find { |job| job[:job] == BackchannelLogoutJob }
    assert job_data, "signing out should enqueue a backchannel logout"
    clear_enqueued_jobs
    job = BackchannelLogoutJob.new(*ActiveJob::Arguments.deserialize(job_data[:args]))

    PrivateAddressCheck.stub(:resolves_to_internal?, false) do
      Net::HTTP.stub(:start, ->(*, **) { raise Net::OpenTimeout }) do
        assert_enqueued_jobs 1, only: BackchannelLogoutJob do
          job.perform_now
        end
      end
    end
  end

  private

  # Runs the enqueued jobs against a stand-in RP and returns each logout token
  # it received, decoded, as [payload, header].
  def logout_tokens_posted
    posted = []
    rp = Object.new
    rp.define_singleton_method(:request) do |request|
      posted << URI.decode_www_form(request.body).to_h.fetch("logout_token")
      Net::HTTPOK.new("1.1", "200", "OK")
    end

    PrivateAddressCheck.stub(:resolves_to_internal?, false) do
      Net::HTTP.stub(:start, ->(*, **, &block) { block.call(rp) }) do
        perform_enqueued_jobs
      end
    end

    posted.map { |token| JWT.decode(token, nil, false) }
  end
end
