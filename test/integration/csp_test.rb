require "test_helper"

class CspTest < ActionDispatch::IntegrationTest
  # In the test env content_security_policy_report_only is false, so the enforcing
  # Content-Security-Policy header is emitted.
  test "signin page sends a nonce-based CSP with no unsafe-inline" do
    get signin_path
    assert_response :success

    csp = response.headers["Content-Security-Policy"]
    assert csp.present?, "expected a Content-Security-Policy header"

    script_src = directive(csp, "script-src")
    style_src = directive(csp, "style-src")

    assert_includes script_src, "'nonce-", "script-src must carry a nonce"
    assert_includes style_src, "'nonce-", "style-src must carry a nonce"
    refute_includes script_src, "'unsafe-inline'", "script-src must not allow unsafe-inline"
    refute_includes style_src, "'unsafe-inline'", "style-src must not allow unsafe-inline"
  end

  test "the inline theme script carries the script-src nonce" do
    get signin_path
    assert_response :success

    header_nonce = response.headers["Content-Security-Policy"][/script-src[^;]*'nonce-([^']+)'/, 1]
    assert header_nonce.present?, "expected a nonce in the CSP header"

    # The hand-written dark-mode <script> in the layout must use the same nonce,
    # otherwise it would be blocked under the enforcing policy.
    assert_match(/<script nonce="#{Regexp.escape(header_nonce)}">/, response.body,
      "inline theme script must carry the matching CSP nonce")
  end

  test "signin page adds the OAuth redirect_uri host to form-action without 500ing" do
    # A user must exist, otherwise /signin redirects to signup before the CSP
    # branch runs.
    User.create!(email_address: "csp_oauth@example.com", password: "password123")

    app = Application.create!(
      name: "CSP OAuth App",
      slug: "csp-oauth-app",
      app_type: "oidc",
      redirect_uris: ["https://app.example.com/callback"].to_json,
      active: true,
      require_pkce: false
    )

    # An unauthenticated authorize request stores the full /oauth/authorize URL
    # in the session and redirects to signin (oidc_controller.rb:202).
    get "/oauth/authorize", params: {
      client_id: app.client_id,
      redirect_uri: app.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid"
    }
    assert_redirected_to signin_path

    # Following to signin must reach allow_oauth_redirect_in_csp without raising.
    # Regression: csp.form_action is a destructive getter, so reading it twice
    # returned nil and `nil << host` raised NoMethodError -> 500.
    follow_redirect!
    assert_response :success

    form_action = directive(response.headers["Content-Security-Policy"], "form-action")
    assert_includes form_action, "'self'", "form-action must keep its default 'self'"
    assert_includes form_action, "https://app.example.com",
      "form-action must include the OAuth client's redirect_uri host"
  end

  test "consent page adds the OAuth redirect_uri host to form-action" do
    # The consent page is where the authorization code is about to be handed
    # over, so form-action is exactly the header that must not go missing.
    # Regression: the authorize action called the destructive `csp.form_action`
    # getter twice, deleting the directive and then raising, so the page shipped
    # with no form-action restriction at all.
    bob = users(:bob)
    app = applications(:kavita_app)
    sign_in_as(bob)

    get "/oauth/authorize", params: {
      client_id: app.client_id,
      redirect_uri: "https://kavita.example.com/signin-oidc",
      response_type: "code",
      scope: "openid"
    }
    assert_response :success

    form_action = directive(response.headers["Content-Security-Policy"], "form-action")
    assert_includes form_action, "'self'", "form-action must keep its default 'self'"
    assert_includes form_action, "https://kavita.example.com",
      "form-action must include the OAuth client's redirect_uri host"
  end

  test "the redirect_uri host does not leak into other requests' form-action" do
    # `request.content_security_policy` returns the application-wide policy
    # object, shared by every request this process serves. Appending to it in
    # place pins the host into every later response — so one unauthenticated
    # visit to /oauth/authorize would widen form-action on every other user's
    # sign-in page, for the life of the worker, growing with each new host seen.
    # With Dynamic Client Registration enabled the host is attacker-chosen.
    User.create!(email_address: "csp_leak@example.com", password: "password123")

    app = Application.create!(
      name: "CSP Leak App",
      slug: "csp-leak-app",
      app_type: "oidc",
      redirect_uris: ["https://leaky.example.com/callback"].to_json,
      active: true,
      require_pkce: false
    )

    get "/oauth/authorize", params: {
      client_id: app.client_id,
      redirect_uri: "https://leaky.example.com/callback",
      response_type: "code",
      scope: "openid"
    }
    assert_redirected_to signin_path
    follow_redirect!
    assert_includes directive(response.headers["Content-Security-Policy"], "form-action"),
      "https://leaky.example.com", "guard precondition: the host is allowed for this request"

    # An unrelated visitor, on an unrelated page, must not inherit it.
    reset!
    get signin_path
    assert_response :success

    form_action = directive(response.headers["Content-Security-Policy"], "form-action")
    assert_includes form_action, "'self'"
    refute_includes form_action, "https://leaky.example.com",
      "a redirect_uri host must not persist into unrelated later responses"
  end

  test "form-action keeps the redirect_uri's scheme and port" do
    # RFC 8252 loopback redirects are accepted at registration, and https on a
    # non-default port is equally valid. Rebuilding the source as "https://host"
    # drops both, yielding a directive that matches neither — which blocks the
    # very redirect this is meant to permit.
    User.create!(email_address: "csp_port@example.com", password: "password123")

    app = Application.create!(
      name: "CSP Loopback App",
      slug: "csp-loopback-app",
      app_type: "oidc",
      redirect_uris: ["http://127.0.0.1:8123/callback"].to_json,
      active: true,
      require_pkce: false
    )

    get "/oauth/authorize", params: {
      client_id: app.client_id,
      redirect_uri: "http://127.0.0.1:8123/callback",
      response_type: "code",
      scope: "openid"
    }
    assert_redirected_to signin_path
    follow_redirect!

    form_action = directive(response.headers["Content-Security-Policy"], "form-action")
    assert_includes form_action, "http://127.0.0.1:8123",
      "form-action must carry the redirect_uri's real origin, scheme and port included"
  end

  private

  def directive(csp, name)
    csp.split(";").map(&:strip).find { |d| d.start_with?("#{name} ") } || ""
  end
end
