require "test_helper"

# ruby-vips binds libvips as soon as it is required. When Bundler.require loads
# it, a missing libvips is a GemRequireError and the app cannot boot, which is
# what happened in the CI jobs that do not install it. Active Storage requires
# ruby-vips itself and rescues a missing libvips, so Bundler must leave it alone.
class LibvipsBootTest < ActiveSupport::TestCase
  test "Bundler does not require ruby-vips at boot" do
    ruby_vips = Bundler.definition.dependencies.find { |dependency| dependency.name == "ruby-vips" }

    assert_equal [], ruby_vips.autorequire
  end
end
