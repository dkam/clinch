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

  # public_addresses on IP literals (no DNS needed) exercises the same
  # address classification used after resolution.
  test "public_addresses classifies IP literals" do
    assert_nil PrivateAddressCheck.public_addresses("169.254.169.254")
    assert_nil PrivateAddressCheck.public_addresses("127.0.0.1")
    assert_equal [IPAddr.new("8.8.8.8")], PrivateAddressCheck.public_addresses("8.8.8.8")
  end

  test "public_addresses refuses a host that resolves to an internal address" do
    PrivateAddressCheck.stub(:addresses, [IPAddr.new("203.0.113.10"), IPAddr.new("10.0.0.5")]) do
      assert_nil PrivateAddressCheck.public_addresses("rp.example.com")
    end
  end

  test "public_addresses doesn't look up a hostname that is internal by name" do
    PrivateAddressCheck.stub(:addresses, ->(_) { flunk "looked up localhost" }) do
      assert_nil PrivateAddressCheck.public_addresses("localhost")
    end
  end
end
