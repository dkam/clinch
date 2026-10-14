require "test_helper"

# OIDC Core §3.1.2.1: prompt is a space-delimited list. With "none" the OP must
# not show any page, and answers with an error instead when it can't issue a
# code silently; silent-renew clients depend on that answer coming back.
class OidcPromptTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app) # alice_consent fixture: openid profile email
    @redirect_uri = @application.parsed_redirect_uris.first
  end

  test "prompt=none without consent answers consent_required" do
    OidcUserConsent.where(user: @user, application: @application).destroy_all
    sign_in_as(@user)

    authorize(prompt: "none")

    assert_error_redirect "consent_required"
  end

  test "prompt=none with an expired max_age answers login_required and keeps the session" do
    sign_in_as(@user)
    session = Current.session

    authorize(prompt: "none", max_age: "0")

    assert_error_redirect "login_required"
    assert Session.exists?(session.id), "a silent check must not sign the user out"
  end

  test "prompt=none for a user without access answers access_denied" do
    sign_in_as(users(:one)) # in no group that may use Kavita

    authorize(prompt: "none")

    assert_error_redirect "access_denied"
  end

  test "prompt=none combined with anything else is refused" do
    sign_in_as(@user)

    authorize(prompt: "none login")

    assert_error_redirect "invalid_request"
  end

  test "prompt=login is honoured when listed with other values" do
    sign_in_as(@user)

    authorize(prompt: "login consent")

    assert_redirected_to signin_path
  end

  test "prompt=consent shows the consent page even when consent was given" do
    sign_in_as(@user)

    authorize(prompt: "consent")

    assert_response :success
    assert_select "form[action='/oauth/authorize/consent']"
  end

  private

  def authorize(**extra)
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @redirect_uri,
      response_type: "code",
      scope: "openid",
      state: "st"
    }.merge(extra)
  end

  def assert_error_redirect(error)
    assert_response :redirect
    location = URI(response.location)
    assert_equal @redirect_uri, "#{location.scheme}://#{location.host}#{location.path}"
    query = Rack::Utils.parse_query(location.query)
    assert_equal error, query["error"]
    assert_equal "st", query["state"]
  end
end
