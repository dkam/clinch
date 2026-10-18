require "test_helper"

# ForwardAuth needs the session cookie on the parent domain (Domain=.example.com),
# so the browser sends it to every app the proxy checks. That also hands the
# IdP session to every sibling subdomain, so the cookie only goes there while
# a ForwardAuth app exists (CLN-10). A cookie is only removed by a deletion that
# names the same domain, so sign-in and sign-out clear both scopes: whichever
# one an earlier sign-in used.
class SessionCookieDomainTest < ActionDispatch::IntegrationTest
  setup do
    host! "auth.example.com"
    @user = users(:alice)
    @application = applications(:kavita_app)
    Application.create!(name: "Proxied", slug: "proxied", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)
  end

  test "the session cookie is set on the parent domain" do
    sign_in

    assert_match(/domain=\.example\.com/i, session_cookie)
  end

  test "without a ForwardAuth app the session cookie stays on the auth host" do
    Application.forward_auth.destroy_all

    sign_in

    assert_no_match(/domain=/i, session_cookie)
  end

  test "signing in on the parent domain clears a host-only cookie" do
    sign_in

    assert host_only_deletion, "a host-only cookie from before the first ForwardAuth app would shadow the new one"
  end

  test "signing in host-only clears a cookie on the parent domain" do
    Application.forward_auth.destroy_all

    sign_in

    assert parent_domain_deletion, "a parent-domain cookie from before the last ForwardAuth app went would linger"
  end

  test "signing out deletes the cookie on both scopes" do
    sign_in

    delete signout_path

    assert parent_domain_deletion, "a deletion without the cookie's domain leaves the browser's copy in place"
    assert host_only_deletion
  end

  test "prompt=login deletes the cookie on the parent domain" do
    sign_in

    authorize(prompt: "login")

    assert_redirected_to signin_path
    assert parent_domain_deletion
  end

  test "an expired max_age deletes the cookie on the parent domain" do
    sign_in

    authorize(max_age: "0")

    assert_redirected_to signin_path
    assert parent_domain_deletion
  end

  private

  def sign_in
    post signin_path, params: {email_address: @user.email_address, password: "password"}
    assert_response :redirect
    assert session_cookie, "signing in should set the session cookie"
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

  def session_cookie_headers
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
      .select { |c| c.start_with?("session_id=") }
  end

  def session_cookie
    session_cookie_headers.find { |c| !deletion?(c) }
  end

  def deletion?(header)
    header.match?(/max-age=0|expires=Thu, 01 Jan 1970/i)
  end

  def parent_domain_deletion
    session_cookie_headers.find { |c| deletion?(c) && c.match?(/domain=\.example\.com/i) && c.match?(/path=\/(;|\z)/i) }
  end

  def host_only_deletion
    session_cookie_headers.find { |c| deletion?(c) && !c.match?(/domain=/i) && c.match?(/path=\/(;|\z)/i) }
  end
end
