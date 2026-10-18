require "test_helper"

# The IdP session cookie stays on the auth host. ForwardAuth needs a cookie the
# browser sends to every app the proxy checks, so while a ForwardAuth app exists
# a second, separately signed cookie goes on the parent domain
# (Domain=.example.com). An app that copies it can pass /api/verify as that user,
# but can't use it as a session on Clinch itself (CLN-10).
#
# Earlier versions put the session cookie itself on the parent domain, and a
# browser only removes a cookie when the deletion names the same domain, so
# sign-in and sign-out clear that copy too.
class SessionCookieDomainTest < ActionDispatch::IntegrationTest
  setup do
    host! "auth.example.com"
    @user = users(:alice)
    @application = applications(:kavita_app)
    Application.create!(name: "Proxied", slug: "proxied", app_type: "forward_auth", domain_pattern: "app.example.com", active: true)
  end

  test "the session cookie stays on the auth host when a ForwardAuth app exists" do
    sign_in

    assert_no_match(/domain=/i, set_cookie("session_id"))
  end

  test "signing in sets the forward-auth cookie on the parent domain" do
    sign_in

    forward_auth = set_cookie("clinch_forward_auth")
    assert forward_auth, "a ForwardAuth app needs a cookie the proxied hosts receive"
    assert_match(/domain=\.example\.com/i, forward_auth)
    assert_match(/path=\/(;|\z)/i, forward_auth)
    assert_match(/httponly/i, forward_auth)
    assert_match(/samesite=lax/i, forward_auth)
  end

  test "without a ForwardAuth app there is no forward-auth cookie" do
    Application.forward_auth.destroy_all

    sign_in

    assert_nil set_cookie("clinch_forward_auth")
    assert_no_match(/domain=/i, set_cookie("session_id"))
  end

  test "the forward-auth cookie lasts as long as a remembered session" do
    sign_in(remember_me: "1")

    expires = set_cookie("clinch_forward_auth")[/expires=([^;]+)/i, 1]
    assert expires, "a remembered session's forward-auth cookie should survive the browser closing"
    assert_in_delta @user.sessions.order(:created_at).last.expires_at, Time.httpdate(expires), 5
  end

  test "without Remember me the forward-auth cookie ends with the browser session" do
    sign_in(remember_me: "0")

    forward_auth = set_cookie("clinch_forward_auth")
    assert forward_auth
    assert_no_match(/expires=/i, forward_auth)
  end

  test "the forward-auth cookie is not accepted as a session on Clinch" do
    sign_in
    forward_auth = cookies["clinch_forward_auth"]
    assert forward_auth.present?

    cookies.delete("session_id")
    cookies["session_id"] = forward_auth
    get root_path

    assert_redirected_to signin_path
  end

  test "signing in clears a session cookie left on the parent domain" do
    sign_in

    assert deletion("session_id", domain: ".example.com"), "an earlier version's parent-domain session cookie would linger"
  end

  test "signing out deletes both cookies" do
    sign_in

    delete signout_path

    assert deletion("session_id", domain: nil)
    assert deletion("session_id", domain: ".example.com"), "a deletion without the cookie's domain leaves the browser's copy in place"
    assert deletion("clinch_forward_auth", domain: ".example.com")
  end

  test "signing out through OIDC logout deletes both cookies" do
    sign_in

    post confirm_logout_path

    assert deletion("session_id", domain: nil), "the session is gone, but the browser would keep sending its cookie"
    assert deletion("clinch_forward_auth", domain: ".example.com")
  end

  test "prompt=login deletes both cookies" do
    sign_in

    authorize(prompt: "login")

    assert_redirected_to signin_path
    assert deletion("session_id", domain: ".example.com")
    assert deletion("clinch_forward_auth", domain: ".example.com")
  end

  test "an expired max_age deletes both cookies" do
    sign_in

    authorize(max_age: "0")

    assert_redirected_to signin_path
    assert deletion("session_id", domain: ".example.com")
    assert deletion("clinch_forward_auth", domain: ".example.com")
  end

  # /api/verify sends a browser with no forward-auth cookie to /signin. One
  # that is signed in on the auth host gets the cookie and goes straight back,
  # which also carries sessions from before this cookie existed across.
  test "a signed-in browser without the forward-auth cookie is sent back with one" do
    sign_in
    cookies.delete("clinch_forward_auth")

    get signin_path, params: {rd: "https://app.example.com/dashboard"}

    assert_response :redirect
    assert_match %r{\Ahttps://app\.example\.com/dashboard\?fa_token=}, response.location
    assert_match(/domain=\.example\.com/i, set_cookie("clinch_forward_auth"))
  end

  test "sending a signed-in browser back moves its session cookie onto the auth host" do
    sign_in

    get signin_path, params: {rd: "https://app.example.com/dashboard"}

    assert_no_match(/domain=/i, set_cookie("session_id"))
    assert deletion("session_id", domain: ".example.com"), "an earlier version's parent-domain session cookie would linger"
  end

  # Sent back to an app the cookie doesn't reach, the browser would arrive
  # without it again, and go round between the app and /signin.
  test "a signed-in browser is not sent back to an app the cookie can't reach" do
    Application.create!(name: "Elsewhere", slug: "elsewhere", app_type: "forward_auth", domain_pattern: "app.example.net", active: true)
    sign_in

    get signin_path, params: {rd: "https://app.example.net/"}

    assert_response :success
  end

  test "reached by IP address, a signed-in browser is sent back only to that host" do
    host! "192.168.1.10"
    Application.create!(name: "Same host", slug: "same-host", app_type: "forward_auth", domain_pattern: "192.168.1.10", active: true)
    sign_in
    assert_no_match(/domain=/i, set_cookie("clinch_forward_auth"))

    get signin_path, params: {rd: "https://192.168.1.10:8443/"}
    assert_response :redirect

    get signin_path, params: {rd: "https://app.example.com/"}
    assert_response :success
  end

  test "a signed-in browser is not sent to a host that isn't a ForwardAuth app" do
    sign_in

    get signin_path, params: {rd: "https://evil.example.net/"}

    assert_response :success
    assert_nil set_cookie("clinch_forward_auth")
  end

  private

  def sign_in(remember_me: "0")
    post signin_path, params: {email_address: @user.email_address, password: "password", remember_me: remember_me}
    assert_response :redirect
    assert set_cookie("session_id"), "signing in should set the session cookie"
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

  def cookie_headers(name)
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
      .select { |c| c.start_with?("#{name}=") }
  end

  def set_cookie(name)
    cookie_headers(name).find { |c| !deletion?(c) }
  end

  def deletion?(header)
    header.match?(/max-age=0|expires=Thu, 01 Jan 1970/i)
  end

  # A deletion with the given domain (nil: host-only) and path "/", which the
  # cookie was set with; left out, the browser would use the request's directory.
  def deletion(name, domain:)
    cookie_headers(name).find do |c|
      deletion?(c) && c.match?(/path=\/(;|\z)/i) &&
        (domain ? c.match?(/domain=#{Regexp.escape(domain)}(;|\z)/i) : !c.match?(/domain=/i))
    end
  end
end
