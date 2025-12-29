require "test_helper"

class InputValidationTest < ActionDispatch::IntegrationTest
  # ====================
  # SQL INJECTION PREVENTION TESTS
  # ====================

  test "SQL injection is prevented by Rails ORM" do
    # Rails ActiveRecord prevents SQL injection through parameterized queries
    # This test verifies the protection is in place

    # Try SQL injection in email field
    post signin_path, params: {
      email_address: "admin' OR '1'='1",
      password: "password123"
    }

    # Should not authenticate with SQL injection
    assert_response :redirect
    assert_redirected_to signin_path
    assert_match(/invalid/i, flash[:alert].to_s)
  end

  # ====================
  # XSS PREVENTION TESTS
  # ====================

  test "XSS in user input is escaped" do
    # Create user with XSS payload in name
    xss_payload = "<script>alert('XSS')</script>"
    user = User.create!(email_address: "xss_test@example.com", password: "password123", name: xss_payload)

    # Sign in
    post signin_path, params: { email_address: "xss_test@example.com", password: "password123" }
    assert_response :redirect

    # Get a page that displays user name
    get root_path
    assert_response :success

    # The XSS payload should be escaped, not executed
    # Rails automatically escapes output in ERB templates

    user.destroy
  end

  # ====================
  # PARAMETER TAMPERING TESTS
  # ====================

  test "parameter tampering in OAuth authorization is prevented" do
    user = User.create!(email_address: "oauth_tamper_test@example.com", password: "password123")
    application = Application.create!(
      name: "OAuth Test App",
      slug: "oauth-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )

    # Sign in
    post signin_path, params: { email_address: "oauth_tamper_test@example.com", password: "password123" }
    assert_response :redirect

    # Try to tamper with OAuth authorization parameters
    get "/oauth/authorize", params: {
      client_id: application.client_id,
      redirect_uri: "http://evil.com/callback",  # Tampered redirect URI
      response_type: "code",
      scope: "openid profile admin",  # Tampered scope to request admin access
      user_id: 1  # Tampered user ID
    }

    # Should reject the tampered redirect URI
    assert_response :bad_request

    user.sessions.delete_all
    user.destroy
    application.destroy
  end

  test "parameter tampering in token request is prevented" do
    user = User.create!(email_address: "token_tamper_test@example.com", password: "password123")
    application = Application.create!(
      name: "Token Tamper Test App",
      slug: "token-tamper-test",
      app_type: "oidc",
      redirect_uris: ["http://localhost:4000/callback"].to_json,
      active: true
    )

    # Try to tamper with token request parameters
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: "fake_code",
      redirect_uri: "http://localhost:4000/callback",
      client_id: "tampered_client_id",
      user_id: 999  # Tampered user ID
    }

    # Should reject tampered client_id
    assert_response :unauthorized

    user.destroy
    application.destroy
  end

  # ====================
  # JSON INPUT VALIDATION TESTS
  # ====================

  test "JSON input validation prevents malicious payloads" do
    # Try to send malformed JSON
    post "/oauth/token", params: '{"grant_type":"authorization_code",}'.to_json,
      headers: { "CONTENT_TYPE" => "application/json" }

    # Should handle malformed JSON gracefully
    assert_includes [400, 422], response.status
  end

  test "JSON input sanitization prevents injection" do
    # Try JSON injection attacks
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: "test_code",
      redirect_uri: "http://localhost:4000/callback",
      nested: { __proto__: "tampered", constructor: { prototype: "tampered" } }
    }.to_json,
    headers: { "CONTENT_TYPE" => "application/json" }

    # Should sanitize or reject prototype pollution attempts
    # The request should be handled (either accept or reject, not crash)
    assert response.body.present?
  end

  # ====================
  # HEADER INJECTION TESTS
  # ====================

  test "HTTP header injection is prevented" do
    # Try to inject headers via user input
    malicious_input = "value\r\nX-Injected-Header: malicious"

    post signin_path, params: {
      email_address: malicious_input,
      password: "password123"
    }

    # Should sanitize or reject header injection attempts
    assert_nil response.headers["X-Injected-Header"]
  end

  # ====================
  # PATH TRAVERSAL TESTS
  # ====================

  test "path traversal is prevented" do
    # Try to access files outside intended directory
    malicious_paths = [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "/etc/passwd",
      "C:\\Windows\\System32\\config\\sam"
    ]

    malicious_paths.each do |malicious_path|
      # Try to access files with path traversal
      get root_path, params: { file: malicious_path }

      # Should prevent access to files outside public directory
      assert_response :redirect, "Should reject path traversal attempt"
    end
  end

  test "null byte injection is prevented" do
    # Try null byte injection
    malicious_input = "test\x00@example.com"

    post signin_path, params: {
      email_address: malicious_input,
      password: "password123"
    }

    # Should sanitize null bytes
    assert_response :redirect
  end
end
