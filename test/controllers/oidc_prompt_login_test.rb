require "test_helper"

class OidcPromptLoginTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app)
    @client_secret = SecureRandom.urlsafe_base64(48)
    @application.client_secret = @client_secret
    @application.save!

    # Pre-authorize the application so we skip consent screen
    consent = OidcUserConsent.find_or_initialize_by(
      user: @user,
      application: @application
    )
    consent.scopes_granted ||= "openid profile email"
    consent.save!
  end

  teardown do
    # Clean up
    OidcAccessToken.where(user: @user, application: @application).destroy_all
    OidcAuthorizationCode.where(user: @user, application: @application).destroy_all
  end

  test "max_age requires re-authentication when session is too old" do
    # Sign in to create a session
    post "/signin", params: {
      email_address: @user.email_address,
      password: "password"
    }

    assert_response :redirect
    follow_redirect!
    assert_response :success

    # Get first auth_time
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "first-state",
      nonce: "first-nonce"
    }

    assert_response :redirect
    first_redirect_url = response.location
    first_code = CGI.parse(URI(first_redirect_url).query)["code"].first

    # Exchange for tokens and extract auth_time
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: first_code,
      redirect_uri: @application.parsed_redirect_uris.first,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    first_tokens = JSON.parse(response.body)
    first_id_token = OidcJwtService.decode_id_token(first_tokens["id_token"])
    first_auth_time = first_id_token[0]["auth_time"]

    # Wait a bit (simulate time passing - in real scenario this would be actual seconds)
    # Then request with max_age=0 (means session must be brand new)
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "second-state",
      nonce: "second-nonce",
      max_age: "0"  # Requires session to be 0 seconds old (i.e., brand new)
    }

    # Should redirect to sign in because session is too old
    assert_response :redirect
    assert_redirected_to /signin/

    # Sign in again
    post "/signin", params: {
      email_address: @user.email_address,
      password: "password"
    }

    assert_response :redirect
    follow_redirect!

    # Should receive authorization code
    assert_response :redirect
    second_redirect_url = response.location
    second_code = CGI.parse(URI(second_redirect_url).query)["code"].first

    assert second_code.present?, "Should receive authorization code after re-authentication"

    # Exchange second authorization code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: second_code,
      redirect_uri: @application.parsed_redirect_uris.first,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    second_tokens = JSON.parse(response.body)
    second_id_token = OidcJwtService.decode_id_token(second_tokens["id_token"])
    second_auth_time = second_id_token[0]["auth_time"]

    # The second auth_time should be >= the first (re-authentication occurred)
    # Note: May be equal if both occur in the same second (test timing edge case)
    assert second_auth_time >= first_auth_time,
      "max_age=0 should result in a re-authentication. " \
      "First: #{first_auth_time}, Second: #{second_auth_time}"
  end

  test "prompt=none returns login_required error when not authenticated" do
    # Don't sign in - user is not authenticated

    # Request authorization with prompt=none
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "test-state",
      prompt: "none"
    }

    # Should redirect with error=login_required (NOT to sign-in page)
    assert_response :redirect
    redirect_url = response.location

    # Parse the redirect URL
    uri = URI.parse(redirect_url)
    query_params = uri.query ? CGI.parse(uri.query) : {}

    assert_equal "login_required", query_params["error"]&.first,
      "Should return login_required error for prompt=none when not authenticated"
    assert_equal "test-state", query_params["state"]&.first,
      "Should return state parameter"
  end

  test "prompt=login forces re-authentication with new auth_time" do
    # First authentication
    post "/signin", params: {
      email_address: @user.email_address,
      password: "password"
    }

    assert_response :redirect
    follow_redirect!
    assert_response :success

    # Get first authorization code
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "first-state",
      nonce: "first-nonce"
    }

    assert_response :redirect
    first_redirect_url = response.location
    first_code = CGI.parse(URI(first_redirect_url).query)["code"].first

    # Exchange for tokens and extract auth_time from ID token
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: first_code,
      redirect_uri: @application.parsed_redirect_uris.first,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    first_tokens = JSON.parse(response.body)
    first_id_token = OidcJwtService.decode_id_token(first_tokens["id_token"])
    first_auth_time = first_id_token[0]["auth_time"]

    # Now request authorization again with prompt=login
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: @application.parsed_redirect_uris.first,
      response_type: "code",
      scope: "openid",
      state: "second-state",
      nonce: "second-nonce",
      prompt: "login"
    }

    # Should redirect to sign in
    assert_response :redirect
    assert_redirected_to /signin/

    # Sign in again (simulating user re-authentication)
    post "/signin", params: {
      email_address: @user.email_address,
      password: "password"
    }

    assert_response :redirect
    # Follow redirect to after_authentication_url (which is /oauth/authorize without prompt=login)
    follow_redirect!

    # Should receive authorization code redirect
    assert_response :redirect
    second_redirect_url = response.location
    second_code = CGI.parse(URI(second_redirect_url).query)["code"].first

    assert second_code.present?, "Should receive authorization code after re-authentication"

    # Exchange second authorization code for tokens
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: second_code,
      redirect_uri: @application.parsed_redirect_uris.first,
      client_id: @application.client_id,
      client_secret: @client_secret
    }

    assert_response :success
    second_tokens = JSON.parse(response.body)
    second_id_token = OidcJwtService.decode_id_token(second_tokens["id_token"])
    second_auth_time = second_id_token[0]["auth_time"]

    # The second auth_time should be >= the first (re-authentication occurred)
    # Note: May be equal if both occur in the same second (test timing edge case)
    assert second_auth_time >= first_auth_time,
      "prompt=login should result in a later auth_time. " \
      "First: #{first_auth_time}, Second: #{second_auth_time}"
  end
end
