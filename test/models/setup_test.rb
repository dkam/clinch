require "test_helper"

class SetupTest < ActiveSupport::TestCase
  test "setup is closed while any user exists" do
    assert User.exists?
    assert_not Setup.open?
  end

  test "setup is open on an empty instance" do
    empty_the_instance

    assert Setup.open?
  end

  test "the code is twelve characters in three groups, from an unambiguous alphabet" do
    assert_match(/\A[#{Setup::ALPHABET}]{4}-[#{Setup::ALPHABET}]{4}-[#{Setup::ALPHABET}]{4}\z/o, Setup.code)
    assert_no_match(/[01OI]/, Setup.code)
  end

  test "the code is the same on every call, so every process agrees on it" do
    assert_equal Setup.code, Setup.code
  end

  test "the code is accepted however it was typed" do
    assert Setup.correct?(Setup.code)
    assert Setup.correct?(Setup.code.downcase)
    assert Setup.correct?(Setup.code.delete("-"))
    assert Setup.correct?(" #{Setup.code.tr("-", " ")} ")
  end

  test "anything else is refused" do
    assert_not Setup.correct?(nil)
    assert_not Setup.correct?("")
    assert_not Setup.correct?("----")
    assert_not Setup.correct?("#{Setup.code}X")
    assert_not Setup.correct?(Setup.code.sub(/\A./) { |c| (c == "Z") ? "Y" : "Z" })
  end

  test "the code is announced on an empty instance" do
    empty_the_instance

    announced = StringIO.new
    Setup.announce(announced)

    assert_includes announced.string, Setup.code
  end

  test "nothing is announced once a user exists" do
    announced = StringIO.new
    Setup.announce(announced)

    assert_empty announced.string
  end

  test "the first account is active and in every admin group" do
    empty_the_instance

    user = Setup.create_admin(email_address: "first@example.com", password: "a good long password", password_confirmation: "a good long password")

    assert user.persisted?
    assert user.active?
    assert user.admin?
    assert_equal Group.admin.pluck(:id).sort, user.groups.admin.pluck(:id).sort
  end

  # The check runs inside the same IMMEDIATE transaction as the insert, so a
  # submission that loses the race to the first one lands here.
  test "no admin is created once a user exists" do
    assert_no_difference -> { User.count } do
      user = Setup.create_admin(email_address: "late@example.com", password: "a good long password", password_confirmation: "a good long password")

      assert_not user.persisted?
      assert_includes user.errors[:base], "Clinch already has an administrator. Please sign in."
    end
  end

  test "an invalid first account creates nobody and grants nothing" do
    empty_the_instance

    assert_no_difference -> { UserGroup.count } do
      user = Setup.create_admin(email_address: "not-an-email", password: "short", password_confirmation: "short")

      assert_not user.persisted?
    end
    assert Setup.open?
  end

  private

  # Tokens hold a foreign key to their user without a dependent: option, so
  # they go first.
  def empty_the_instance
    [OidcRefreshToken, OidcAccessToken, OidcAuthorizationCode, OidcDeviceCode].each(&:delete_all)
    User.destroy_all
  end
end
