require "test_helper"

# OpenID Connect RP-Initiated Logout 1.0. Signing someone out is a state change
# any page could trigger with an image tag, so Clinch does it straight away
# only when the request carries an ID token it issued to the signed-in user;
# otherwise it asks. A post-logout redirect must belong to the client asking.
class OidcLogoutTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app) # alice_consent fixture
    @logout_uri = "https://kavita.example.com/signout-callback-oidc"
    sign_in_as(@user)
    @session = Current.session
  end

  test "a valid id_token_hint for the signed-in user signs them out and redirects" do
    get "/logout", params: {id_token_hint: id_token_for(@user), post_logout_redirect_uri: @logout_uri, state: "st"}

    assert_redirected_to "#{@logout_uri}?state=st"
    assert_not Session.exists?(@session.id)
  end

  test "an expired id_token_hint still counts" do
    hint = id_token_for(@user)

    travel 2.hours do # past the ID token's hour, within the session
      get "/logout", params: {id_token_hint: hint}
    end

    assert_not Session.exists?(@session.id)
  end

  test "a hint for someone else asks first" do
    OidcUserConsent.record!(user: users(:bob), application: @application, scopes: %w[openid])

    get "/logout", params: {id_token_hint: id_token_for(users(:bob))}

    assert_response :success
    assert Session.exists?(@session.id)
  end

  test "a hint Clinch didn't sign asks first" do
    payload = JWT.decode(id_token_for(@user), nil, false).first
    forged = JWT.encode(payload, OpenSSL::PKey::RSA.new(2048), "RS256")

    get "/logout", params: {id_token_hint: forged}

    assert_response :success
    assert Session.exists?(@session.id)
  end

  test "a post-logout redirect to another client's URI isn't followed" do
    other = grant_everyone_access(Application.create!(
      name: "Other RP", slug: "other-rp", app_type: "oidc",
      redirect_uris: ["https://other.example.com/bye"].to_json, active: true
    ))

    get "/logout", params: {id_token_hint: id_token_for(@user), post_logout_redirect_uri: other.parsed_redirect_uris.first}

    assert_redirected_to root_path
    assert_not Session.exists?(@session.id)
  end

  test "confirming on the page signs the user out and follows the client's redirect" do
    get "/logout", params: {client_id: @application.client_id, post_logout_redirect_uri: @logout_uri, state: "st"}
    assert_response :success
    assert Session.exists?(@session.id)

    post "/logout/confirm", params: {client_id: @application.client_id, post_logout_redirect_uri: @logout_uri, state: "st"}

    assert_redirected_to "#{@logout_uri}?state=st"
    assert_not Session.exists?(@session.id)
  end

  test "the confirmation can't be submitted from another site" do
    ActionController::Base.allow_forgery_protection = true

    post "/logout/confirm", params: {client_id: @application.client_id}

    assert_response :unprocessable_entity
    assert Session.exists?(@session.id)
  ensure
    ActionController::Base.allow_forgery_protection = false
  end

  private

  def id_token_for(user)
    consent = OidcUserConsent.find_by(user: user, application: @application)
    OidcJwtService.generate_id_token(user, @application, consent: consent)
  end
end
