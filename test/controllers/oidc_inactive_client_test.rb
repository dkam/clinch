require "test_helper"

# Deactivating a client has to stop it working, including as a way to bounce
# a browser from Clinch's origin to wherever the client registered. Errors for
# an inactive client are shown on Clinch's own page, as for an unknown one
# (RFC 6749 §4.1.2.1), instead of being redirected to its redirect URI.
class OidcInactiveClientTest < ActionDispatch::IntegrationTest
  setup do
    @application = grant_everyone_access(Application.create!(
      name: "Retired Client",
      slug: "retired-client",
      app_type: "oidc",
      redirect_uris: ["https://elsewhere.example/land"].to_json,
      active: true,
      require_pkce: false
    ))
  end

  test "an inactive client's authorization errors don't redirect" do
    @application.update!(active: false)

    get "/oauth/authorize", params: authorize_params(response_type: "bogus")

    assert_response :bad_request
    assert_nil response.location
  end

  test "an inactive client doesn't redirect a signed-in user" do
    @application.update!(active: false)
    sign_in_as(users(:alice))

    get "/oauth/authorize", params: authorize_params

    assert_response :bad_request
    assert_nil response.location
  end

  test "a client deactivated while its consent page was open doesn't redirect" do
    sign_in_as(users(:alice))
    get "/oauth/authorize", params: authorize_params
    assert_response :success

    @application.update!(active: false)
    post "/oauth/authorize/consent"

    assert_response :bad_request
    assert_nil response.location
  end

  private

  def authorize_params(**overrides)
    {
      client_id: @application.client_id,
      redirect_uri: "https://elsewhere.example/land",
      response_type: "code",
      scope: "openid",
      state: "st"
    }.merge(overrides)
  end
end
