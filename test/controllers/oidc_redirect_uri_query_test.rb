require "test_helper"

# RFC 6749 §3.1.2: a redirect URI may carry a query component, which MUST be
# retained when Clinch adds its own parameters.
class OidcRedirectUriQueryTest < ActionDispatch::IntegrationTest
  REDIRECT_URI = "https://rp.example.com/callback?tenant=a"

  setup do
    @user = users(:alice)
    @application = grant_everyone_access(Application.create!(
      name: "Query RP",
      slug: "query-rp",
      app_type: "oidc",
      redirect_uris: [REDIRECT_URI].to_json,
      active: true,
      require_pkce: false
    ))
    sign_in_as(@user)
  end

  test "a code issued for an existing consent keeps the redirect URI's query" do
    OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])

    authorize

    assert_redirect_keeps_query
  end

  test "a code issued from the consent page keeps the redirect URI's query" do
    authorize
    assert_response :success

    post "/oauth/authorize/consent"

    assert_redirect_keeps_query
  end

  test "a post-logout redirect keeps the redirect URI's query" do
    consent = OidcUserConsent.record!(user: @user, application: @application, scopes: %w[openid])
    hint = OidcJwtService.generate_id_token(@user, @application, consent: consent)

    get "/logout", params: {id_token_hint: hint, post_logout_redirect_uri: REDIRECT_URI, state: "st"}

    assert_response :redirect
    query = Rack::Utils.parse_query(URI(response.location).query)
    assert_equal "a", query["tenant"]
    assert_equal "st", query["state"]
  end

  private

  def authorize
    get "/oauth/authorize", params: {
      client_id: @application.client_id,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      state: "st"
    }
  end

  def assert_redirect_keeps_query
    assert_response :redirect
    location = URI(response.location)
    assert_equal "/callback", location.path
    query = Rack::Utils.parse_query(location.query)
    assert_equal "a", query["tenant"]
    assert query["code"].present?
    assert_equal "st", query["state"]
  end
end
