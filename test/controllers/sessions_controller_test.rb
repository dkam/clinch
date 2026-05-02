require "test_helper"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  setup { @user = User.take }

  test "new" do
    get new_session_path
    assert_response :success
  end

  test "create with valid credentials" do
    post session_path, params: {email_address: @user.email_address, password: "password"}

    assert_redirected_to root_path
    assert cookies[:session_id]
  end

  test "create with invalid credentials" do
    post session_path, params: {email_address: @user.email_address, password: "wrong"}

    assert_redirected_to signin_path
    assert_nil cookies[:session_id]
  end

  test "destroy" do
    sign_in_as(User.take)

    delete session_path

    assert_redirected_to signin_path
    assert_empty cookies[:session_id]
  end

  test "session cookie has no Expires attribute when remember_me is off" do
    post session_path, params: {email_address: @user.email_address, password: "password", remember_me: "0"}

    set_cookie = Array(response.headers["Set-Cookie"]).find { |c| c.start_with?("session_id=") }
    assert set_cookie, "session_id cookie should be set"
    refute_match(/expires=/i, set_cookie,
      "without Remember me, the session cookie must be a browser-session cookie (no Expires)")
  end

  test "session cookie has long-lived Expires attribute when remember_me is on" do
    post session_path, params: {email_address: @user.email_address, password: "password", remember_me: "1"}

    set_cookie = Array(response.headers["Set-Cookie"]).find { |c| c.start_with?("session_id=") }
    assert set_cookie, "session_id cookie should be set"
    assert_match(/expires=/i, set_cookie,
      "with Remember me, the cookie should have an Expires attribute")
  end
end
