require "uri"
require "public_suffix"
require "ipaddr"

module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :authenticated?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  # Read by /api/verify in place of the session cookie (CLN-10).
  FORWARD_AUTH_COOKIE = :clinch_forward_auth

  private

  def authenticated?
    resume_session
  end

  def require_authentication
    resume_session || request_authentication
  end

  def resume_session
    Current.session ||= find_session_by_cookie
  end

  def find_session_by_cookie
    Session.active.for_active_user.find_by(id: cookies.signed[:session_id]) if cookies.signed[:session_id]
  end

  def request_authentication
    session[:return_to_after_authenticating] = request.url
    redirect_to signin_path
  end

  def after_authentication_url
    session.delete(:return_to_after_authenticating) || root_url
  end

  # When a sign-in form will eventually redirect through /oauth/authorize to an
  # external client, Safari enforces CSP form-action against every hop in the
  # redirect chain. With the default form-action 'self', the final cross-origin
  # hop to the OAuth client's redirect_uri gets blocked. Add the redirect_uri
  # host to form-action so the chain completes.
  def allow_oauth_redirect_in_csp
    stored = session[:return_to_after_authenticating]
    return if stored.blank?

    uri = URI.parse(stored)
    return unless uri.path&.start_with?("/oauth/")

    redirect_uri = Rack::Utils.parse_query(uri.query.to_s)["redirect_uri"]
    return if redirect_uri.blank?

    allow_form_action_for_redirect_uri(redirect_uri)
  rescue URI::InvalidURIError
    nil
  end

  # Append the origin of `redirect_uri` to *this response's* form-action directive.
  #
  # NOTE: `csp.form_action` (no args) is destructive — it deletes the directive
  # and returns its old value, so reading it twice yields nil, and appending to
  # that nil raises. Mutate the underlying `directives` hash (a public reader of
  # the real values) instead. Getting this wrong drops form-action from the
  # response entirely, which is the opposite of what the caller intended.
  #
  # NOTE: `request.content_security_policy` hands back the *application-wide*
  # policy object, shared by every request this process serves. Appending to it
  # in place would pin the host into every later response — one visit to
  # /oauth/authorize widening form-action on every other user's sign-in page for
  # the life of the worker, accumulating a new entry per distinct host seen. The
  # authorize endpoint is reachable unauthenticated and, with Dynamic Client
  # Registration enabled, the host is attacker-chosen. So swap in a per-request
  # copy first: ContentSecurityPolicy#initialize_copy deep-dups the directives,
  # making the copy independent of the global.
  def allow_form_action_for_redirect_uri(redirect_uri)
    return if redirect_uri.blank?

    origin = form_action_origin(URI.parse(redirect_uri))
    return if origin.blank?

    csp = request.content_security_policy
    return unless csp

    csp = csp.dup
    request.content_security_policy = csp

    form_action = (csp.directives["form-action"] ||= ["'self'"])
    form_action << origin unless form_action.include?(origin)
  rescue URI::InvalidURIError
    nil
  end

  # The CSP host-source for a redirect URI. URI::HTTP#origin gives scheme, host
  # and — only when it isn't the scheme's default — port, which is exactly the
  # host-source grammar. Keeping the scheme and port matters: RFC 8252 loopback
  # redirects (http://127.0.0.1:PORT/…) are accepted at registration, and https
  # on a non-default port is equally valid, so a bare "https://#{host}" would
  # match neither and block the redirect this exists to permit. Non-HTTP schemes
  # (native app callbacks) have no host and are skipped, as they were before.
  def form_action_origin(uri)
    return nil unless uri.is_a?(URI::HTTP)
    return nil if uri.host.blank?

    uri.origin
  end

  def start_new_session_for(user, acr: "1", remember_me: false)
    user.update!(last_sign_in_at: Time.current)
    user.sessions.create!(user_agent: request.user_agent, ip_address: request.remote_ip, acr: acr, remember_me: remember_me).tap do |session|
      Current.session = session
      note_authentication
      write_session_cookies(session)

      # Create a one-time token for immediate forward auth after authentication
      # This solves the race condition where browser hasn't processed cookie yet
      create_forward_auth_token(session)
    end
  end

  def terminate_session
    Current.session&.destroy
    Current.session = nil
    delete_session_cookies
  end

  # The session cookie stays on the auth host. ForwardAuth needs a cookie the
  # browser sends to every app the proxy checks, so while a ForwardAuth app
  # exists a second one goes on the parent domain. Rails signs a cookie for its
  # name, so an app that copies that one can't present it as the session cookie.
  def write_session_cookies(session)
    options = {value: session.id, httponly: true, same_site: :lax, secure: Rails.env.production?}

    # When "Remember me" is off, issue a browser-session cookie (no Expires)
    # so closing the browser signs the user out — especially important on
    # shared devices. The server Session#expires_at still enforces the
    # 24h / 30d window regardless.
    #
    # The jar signs the value in place, so each cookie gets its own copy.
    (session.remember_me ? cookies.signed.permanent : cookies.signed)[:session_id] = options.dup
    expire_parent_domain_session_cookie

    if Application.forward_auth.exists?
      forward_auth = options.merge(domain: parent_cookie_domain)
      forward_auth[:expires] = session.expires_at if session.remember_me
      cookies.signed[FORWARD_AUTH_COOKIE] = forward_auth
    end
  end

  def delete_session_cookies
    cookies.delete(:session_id)
    expire_parent_domain_session_cookie
    cookies.delete(FORWARD_AUTH_COOKIE, domain: parent_cookie_domain)
  end

  # Whether the forward-auth cookie, set from this host, reaches `host`.
  def forward_auth_cookie_reaches?(host)
    host = host.to_s.downcase
    root = parent_cookie_domain
    root ? ".#{host}".end_with?(root) : host == request.host.downcase
  end

  # Where the forward-auth cookie goes: this host's parent domain, or this host
  # alone (nil) when it has none, as with an IP address or localhost.
  def parent_cookie_domain
    return @parent_cookie_domain if defined?(@parent_cookie_domain)
    @parent_cookie_domain = extract_root_domain(request.host)
  end

  # Earlier versions put the session cookie on the parent domain, and a browser
  # only removes a cookie when the deletion names the same domain. The jar
  # holds one header per cookie name, already taken by the host-only cookie, so
  # this deletion goes on the response directly. Its path has to match the
  # cookie's; left out, the browser would use the request's directory.
  def expire_parent_domain_session_cookie
    return unless parent_cookie_domain
    response.delete_cookie("session_id", domain: parent_cookie_domain, path: "/")
  end

  # An administrator can require 2FA of someone who hasn't enrolled yet. They
  # can't have a session until they have, so the step that proved their
  # password (signing in, or accepting an invitation) leaves their id here
  # instead, and TotpController lets them enrol on the strength of it. Longer
  # than a half-finished sign-in: they may have to install an authenticator.
  PENDING_TOTP_SETUP_TTL = 15.minutes

  def begin_required_totp_setup(user)
    session[:pending_totp_setup_user_id] = user.id
    session[:pending_totp_setup_started_at] = Time.current.to_i
  end

  def pending_totp_setup_user
    started_at = session[:pending_totp_setup_started_at]
    return unless started_at.present? && Time.at(started_at.to_i) > PENDING_TOTP_SETUP_TTL.ago

    User.active.find_by(id: session[:pending_totp_setup_user_id])
  end

  def clear_pending_totp_setup
    session.delete(:pending_totp_setup_user_id)
    session.delete(:pending_totp_setup_started_at)
    session.delete(:totp_setup_completed_by)
  end

  # Extract root domain for the forward-auth cookie.
  #
  # PURPOSE: The forward-auth cookie goes on this domain so the browser sends it
  # to every app behind ForwardAuth (e.g., .example.com reaches both
  # app.example.com and api.example.com). The session cookie itself stays on
  # the auth host (CLN-10).
  #
  # CRITICAL: Returns nil for IP addresses (IPv4 and IPv6) and localhost - this is intentional!
  # When accessing services by IP, there are no subdomains to share cookies with,
  # and setting a domain cookie would break authentication.
  #
  # Uses the Public Suffix List (industry standard maintained by Mozilla) to
  # correctly handle complex domain patterns like co.uk, com.au, appspot.com, etc.
  #
  # Examples:
  # - app.example.com -> .example.com (enables cross-subdomain SSO)
  # - api.example.co.uk -> .example.co.uk (handles complex TLDs)
  # - myapp.appspot.com -> .myapp.appspot.com (handles platform domains)
  # - localhost -> nil (local development, no domain cookie)
  # - 192.168.1.1 -> nil (IP access, no domain cookie - prevents SSO breakage)
  #
  # @param host [String] The request host (may include port)
  # @return [String, nil] Root domain with leading dot for cookies, or nil for no domain setting
  def extract_root_domain(host)
    return nil if host.blank? || host.match?(/^(localhost|127\.0\.0\.1|::1)$/)

    # Strip port number for domain parsing
    host_without_port = host.split(":").first

    # Check if it's an IP address (IPv4 or IPv6) - if so, don't set domain cookie
    begin
      return nil if IPAddr.new(host_without_port)
    rescue
      false
    end

    # Use Public Suffix List for accurate domain parsing
    domain = PublicSuffix.parse(host_without_port)
    ".#{domain.domain}"
  rescue PublicSuffix::DomainInvalid
    # Fallback for invalid domains or IPs
    nil
  end

  # Create a one-time token for forward auth to handle the race condition
  # where the browser hasn't processed the session cookie yet.
  def create_forward_auth_token(session_obj)
    return_to = session[:return_to_after_authenticating]
    return if return_to.blank?

    session[:return_to_after_authenticating] = with_forward_auth_token(return_to, session_obj)
  end

  # `url` with a one-time fa_token added.
  #
  # The token is bound to the destination host so that anyone who observes
  # the token (Referer leaks, access logs, JS monitors) cannot redeem it for
  # a different application within the 60-second TTL.
  def with_forward_auth_token(url, session_obj)
    uri = URI.parse(url)

    # OAuth flow handles its own session propagation — no fa_token needed.
    return url if uri.path&.start_with?("/oauth/")

    # Path-only URLs are same-origin on Clinch; the cookie race doesn't apply
    # and we have no destination host to bind against.
    bound_host = uri.hostname&.downcase
    return url if bound_host.blank?

    token = SecureRandom.urlsafe_base64(32)
    Rails.cache.write(
      "forward_auth_token:#{token}",
      {session_id: session_obj.id, host: bound_host},
      expires_in: 60.seconds
    )

    query_params = URI.decode_www_form(uri.query || "").to_h
    query_params["fa_token"] = token
    uri.query = URI.encode_www_form(query_params)
    uri.to_s
  end
end
