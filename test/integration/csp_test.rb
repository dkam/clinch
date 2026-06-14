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

  private

  def directive(csp, name)
    csp.split(";").map(&:strip).find { |d| d.start_with?("#{name} ") } || ""
  end
end
