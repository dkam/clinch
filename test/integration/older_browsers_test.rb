require "test_helper"

# An identity provider sits in front of everything else, so a browser it turns
# away can't use any app behind it either.
class OlderBrowsersTest < ActionDispatch::IntegrationTest
  IOS_16_SAFARI = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 " \
    "(KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"

  test "older Safari can reach the sign-in page" do
    get signin_path, headers: {"User-Agent" => IOS_16_SAFARI}

    assert_response :success
  end

  test "ForwardAuth answers for older Safari" do
    app = grant_everyone_access(Application.create!(name: "Old Browser App", slug: "old-browser-app", app_type: "forward_auth", domain_pattern: "old.example.com", active: true))
    sign_in_as(users(:bob))

    get "/api/verify", headers: {"User-Agent" => IOS_16_SAFARI, "X-Forwarded-Host" => app.domain_pattern}

    assert_response :success
  end
end
