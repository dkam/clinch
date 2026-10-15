require "test_helper"

# The session cookie is set on the parent domain (Domain=.example.com) so that
# ForwardAuth works across subdomains. A cookie is only removed by a deletion
# that names the same domain: one without it leaves the browser holding the
# old cookie after sign-out (CLN-10).
class SessionCookieDomainTest < ActionDispatch::IntegrationTest
  setup do
    host! "auth.example.com"
    @user = users(:alice)
    @application = applications(:kavita_app)
  end

  test "the session cookie is set on the parent domain" do
    sign_in

    assert_match(/domain=\.example\.com/i, session_cookie_header)
  end

  test "signing out deletes the cookie on the parent domain" do
    sign_in

    delete signout_path

    assert_deleted_on_parent_domain
  end

  test "prompt=login deletes the cookie on the parent domain" do
    sign_in

    authorize(prompt: "login")

    assert_redirected_to signin_path
    assert_deleted_on_parent_domain
  end

  test "an expired max_age deletes the cookie on the parent domain" do
    sign_in

    authorize(max_age: "0")

    assert_redirected_to signin_path
    assert_deleted_on_parent_domain
  end

  private

  def sign_in
    post signin_path, params: {email_address: @user.email_address, password: "password"}
    assert_response :redirect
    assert session_cookie_header, "signing in should set the session cookie"
  end

  def authorize(**extra)
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "st"
    }.merge(extra)
  end

  def session_cookie_header
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
      .find { |c| c.start_with?("session_id=") }
  end

  def assert_deleted_on_parent_domain
    header = session_cookie_header
    assert header, "the response should delete the session cookie"
    assert_match(/max-age=0|expires=Thu, 01 Jan 1970/i, header)
    assert_match(/domain=\.example\.com/i, header,
      "a deletion without the cookie's domain leaves the browser's copy in place")
  end
end
