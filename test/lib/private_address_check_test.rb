require "test_helper"

class PrivateAddressCheckTest < ActiveSupport::TestCase
  # internal_host? — DNS-free checks on IP literals and known hostnames
  test "flags loopback, private, and link-local IP literals as internal" do
    %w[
      127.0.0.1
      10.0.0.1
      172.16.5.5
      192.168.1.1
      169.254.169.254
      0.0.0.0
      ::1
    ].each do |host|
      assert PrivateAddressCheck.internal_host?(host), "expected #{host} to be internal"
    end
  end

  test "flags localhost-style hostnames as internal" do
    assert PrivateAddressCheck.internal_host?("localhost")
    assert PrivateAddressCheck.internal_host?("foo.localhost")
    assert PrivateAddressCheck.internal_host?("metadata.google.internal")
    assert PrivateAddressCheck.internal_host?("")
  end

  test "does not flag public IP literals as internal" do
    refute PrivateAddressCheck.internal_host?("8.8.8.8")
    refute PrivateAddressCheck.internal_host?("1.1.1.1")
  end

  # resolves_to_internal? on IP literals (no DNS needed) exercises the same
  # address classification used after resolution.
  test "resolves_to_internal? classifies IP literals" do
    assert PrivateAddressCheck.resolves_to_internal?("169.254.169.254")
    assert PrivateAddressCheck.resolves_to_internal?("127.0.0.1")
    refute PrivateAddressCheck.resolves_to_internal?("8.8.8.8")
  end
end
