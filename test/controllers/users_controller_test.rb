require "test_helper"

class UsersControllerTest < ActionDispatch::IntegrationTest
  test "signup is closed once any user exists" do
    get signup_path
    assert_redirected_to signin_path

    assert_no_difference -> { User.count } do
      post signup_path, params: signup_params
    end
    assert_redirected_to signin_path
  end

  test "an empty instance asks for the setup code, but never shows it" do
    empty_the_instance

    get signup_path

    assert_response :success
    assert_select "input[name=?]", "setup_code"
    assert_no_match Setup.code, response.body
  end

  test "the right code creates an admin and signs them in" do
    empty_the_instance

    assert_difference -> { User.count }, 1 do
      post signup_path, params: signup_params
    end

    assert_redirected_to root_path
    user = User.sole
    assert_equal "first@example.com", user.email_address
    assert user.admin?

    get root_path
    assert_response :success
  end

  test "signup closes behind the first user" do
    empty_the_instance
    post signup_path, params: signup_params
    delete signout_path

    get signup_path

    assert_redirected_to signin_path
  end

  test "a wrong code creates nobody and keeps the email" do
    empty_the_instance

    assert_no_difference -> { User.count } do
      post signup_path, params: signup_params(setup_code: "ZZZZ-ZZZZ-ZZZZ")
    end

    assert_response :unprocessable_entity
    assert_match "doesn&#39;t match the one in the server&#39;s log", response.body
    assert_select "input[name=?][value=?]", "user[email_address]", "first@example.com"
    assert Setup.open?
  end

  test "a missing code creates nobody" do
    empty_the_instance

    assert_no_difference -> { User.count } do
      post signup_path, params: signup_params.except(:setup_code)
    end

    assert_response :unprocessable_entity
  end

  test "the right code with an invalid account creates nobody" do
    empty_the_instance

    assert_no_difference -> { User.count } do
      post signup_path, params: signup_params(user: {email_address: "not-an-email", password: "short", password_confirmation: "short"})
    end

    assert_response :unprocessable_entity
    assert Setup.open?
  end

  private

  # Tokens hold a foreign key to their user without a dependent: option, so
  # they go first.
  def empty_the_instance
    [OidcRefreshToken, OidcAccessToken, OidcAuthorizationCode, OidcDeviceCode].each(&:delete_all)
    User.destroy_all
  end

  def signup_params(setup_code: Setup.code, user: nil)
    {
      setup_code: setup_code,
      user: user || {
        email_address: "first@example.com",
        password: "a good long password",
        password_confirmation: "a good long password"
      }
    }
  end
end
