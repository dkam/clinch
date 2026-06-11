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

  private

  def directive(csp, name)
    csp.split(";").map(&:strip).find { |d| d.start_with?("#{name} ") } || ""
  end
end
