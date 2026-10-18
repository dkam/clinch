module SessionTestHelper
  def sign_in_as(user, cookie: :session_id)
    Current.session = user.sessions.create!

    ActionDispatch::TestRequest.create.cookie_jar.tap do |cookie_jar|
      cookie_jar.signed[cookie] = Current.session.id
      cookies[cookie.to_s] = cookie_jar[cookie]
    end
  end

  # What an app behind the proxy receives after its user signs in: the
  # forward-auth cookie, and not the session cookie, which stays on the auth host.
  def sign_in_to_forward_auth_as(user)
    sign_in_as(user, cookie: Authentication::FORWARD_AUTH_COOKIE)
  end

  # sign_in_as sets only the session cookie. Adding an API key, passkey or
  # authenticator also needs a recently confirmed password (RecentAuthentication).
  def confirm_password(password = "password")
    post "/reauthenticate", params: {password: password}
  end

  def sign_out
    Current.session&.destroy!
    cookies.delete("session_id")
  end

  # The last response's Set-Cookie headers for the cookie `name`.
  def response_cookies(name)
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
      .select { |c| c.start_with?("#{name}=") }
  end

  # The header setting `name`, not a deletion sent alongside it.
  def response_cookie_set(name)
    response_cookies(name).find { |c| !cookie_deletion?(c) }
  end

  # The deletion of `name` under the given domain (nil: host-only) and path "/",
  # which the cookie is set with; left out, the browser would use the request's
  # directory.
  def response_cookie_deletion(name, domain:)
    response_cookies(name).find do |c|
      cookie_deletion?(c) && c.match?(/path=\/(;|\z)/i) &&
        (domain ? c.match?(/domain=#{Regexp.escape(domain)}(;|\z)/i) : !c.match?(/domain=/i))
    end
  end

  def cookie_deletion?(header)
    header.match?(/max-age=0|expires=Thu, 01 Jan 1970/i)
  end

  # Attach the auto-assign "everyone" group to the given app so existing tests
  # written under the old "empty allowed_groups = public" rule keep working.
  # New tests should attach groups explicitly to model real access intent.
  def grant_everyone_access(app)
    everyone = begin
      groups(:everyone)
    rescue
      Group.find_by(auto_assign: true)
    end
    app.allowed_groups << everyone unless app.allowed_groups.include?(everyone)
    app
  end
end

ActiveSupport.on_load(:action_dispatch_integration_test) do
  include SessionTestHelper
end
