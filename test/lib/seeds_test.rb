require "test_helper"

# db:prepare loads the seeds when it creates a fresh database, which is the
# first boot of every new install, and whatever they print lands in the
# container's logs.
class SeedsTest < ActiveSupport::TestCase
  test "seeding a fresh install creates no applications and prints nothing" do
    assert_no_difference -> { Application.count } do
      assert_output("", "") { load Rails.root.join("db/seeds.rb") }
    end
  end
end
