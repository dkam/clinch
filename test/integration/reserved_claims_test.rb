require "test_helper"

# Custom claims (group, user, per-app) are merged into ID tokens and userinfo
# responses. They must never shadow a claim Clinch sets itself: a group claim
# {"acr":"2"} would otherwise make every member look as if they had used a
# second factor.
class ReservedClaimsTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:alice)
    @application = applications(:kavita_app) # alice_consent fixture
    @consent = oidc_user_consents(:alice_consent)
    @group = groups(:admin_group)
    @user.groups << @group unless @user.groups.include?(@group)
  end

  test "custom claims can't use the names Clinch sets itself" do
    %w[acr auth_time at_hash sid updated_at].each do |name|
      assert_not Group.new(name: "claims-#{name}", custom_claims: {name => "x"}).valid?, "group claim #{name}"
      assert_not User.new(email_address: "claims-#{name}@example.com", password: "password123", custom_claims: {name => "x"}).valid?, "user claim #{name}"
      assert_not ApplicationUserClaim.new(user: @user, application: @application, custom_claims: {name => "x"}).valid?, "app claim #{name}"
    end
  end

  test "a reserved name saved before it was reserved doesn't reach the ID token" do
    @group.update_column(:custom_claims, {"acr" => "2", "iss" => "https://evil.example", "sid" => "forged"})

    token = OidcJwtService.generate_id_token(@user, @application, consent: @consent, acr: "1")
    json = Base64.urlsafe_decode64(token.split(".")[1])

    assert_equal 1, json.scan('"acr":').size
    assert_equal 1, json.scan('"iss":').size
    assert_equal 1, json.scan('"sid":').size
    payload = JSON.parse(json)
    assert_equal "1", payload["acr"]
    assert_equal @consent.sid, payload["sid"]
  end

  test "a reserved name saved before it was reserved doesn't reach userinfo" do
    @group.update_column(:custom_claims, {"updated_at" => 0})
    token = OidcAccessToken.create!(application: @application, user: @user, scope: "openid profile")

    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}

    assert_response :success
    assert_equal 1, response.body.scan('"updated_at":').size
    assert_equal @user.reload.updated_at.to_i, JSON.parse(response.body)["updated_at"]
  end

  test "the claims parameter leaves out custom claims nobody asked for" do
    @user.update!(custom_claims: {"department" => "eng"})

    token = OidcJwtService.generate_id_token(@user, @application, scopes: "openid email",
      claims_requests: {"id_token" => {"email" => nil}})

    assert_not JWT.decode(token, nil, false).first.key?("department")
  end

  test "the claims parameter's value constraint applies to custom claims" do
    @user.update!(custom_claims: {"department" => "eng"})

    wrong = OidcJwtService.generate_id_token(@user, @application,
      claims_requests: {"id_token" => {"department" => {"value" => "sales"}}})
    right = OidcJwtService.generate_id_token(@user, @application,
      claims_requests: {"id_token" => {"department" => {"value" => "eng"}}})

    assert_not JWT.decode(wrong, nil, false).first.key?("department")
    assert_equal "eng", JWT.decode(right, nil, false).first["department"]
  end

  test "the claims parameter leaves out custom claims nobody asked for at userinfo" do
    @user.update!(custom_claims: {"department" => "eng"})
    @consent.update!(claims_requests: {"userinfo" => {"email" => nil}})
    token = OidcAccessToken.create!(application: @application, user: @user, scope: "openid email")

    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}

    assert_response :success
    assert_not JSON.parse(response.body).key?("department")
  end
end
