require "test_helper"
require "minitest/mock"

class BackchannelLogoutJobTest < ActiveJob::TestCase
  PUBLIC_ADDRESS = IPAddr.new("203.0.113.10")

  # CLN-18: the job checks where the RP's hostname points, so it has to dial
  # that same address. Handed the hostname, Net::HTTP looks it up again, and a
  # hostile DNS server can answer with an internal address the second time.
  test "connects to the address that passed the check, not a fresh lookup" do
    dialled = []
    refuse = ->(host, *, **) {
      dialled << host
      raise Errno::ECONNREFUSED
    }

    PrivateAddressCheck.stub(:addresses, [PUBLIC_ADDRESS]) do
      TCPSocket.stub(:open, refuse) do
        perform("https://rp.example.com/backchannel-logout")
      end
    end

    assert_equal [PUBLIC_ADDRESS.to_s], dialled
  end

  test "refuses an RP whose hostname resolves to an internal address" do
    dialled = false

    PrivateAddressCheck.stub(:addresses, [PUBLIC_ADDRESS, IPAddr.new("10.0.0.5")]) do
      Net::HTTP.stub(:start, ->(*, **) { dialled = true }) do
        perform("https://rp.example.com/backchannel-logout")
      end
    end

    refute dialled, "a hostname with any internal address must not be dialled"
  end

  # Back-Channel Logout 1.0 lets backchannel_logout_uri carry a query string.
  test "posts to the logout URI's path and query" do
    paths = []
    rp = Object.new
    rp.define_singleton_method(:request) do |request|
      paths << request.path
      Net::HTTPOK.new("1.1", "200", "OK")
    end

    PrivateAddressCheck.stub(:addresses, [PUBLIC_ADDRESS]) do
      Net::HTTP.stub(:start, ->(*, **, &block) { block.call(rp) }) do
        perform("https://rp.example.com/backchannel-logout?tenant=7")
      end
    end

    assert_equal ["/backchannel-logout?tenant=7"], paths
  end

  private

  def perform(logout_uri)
    BackchannelLogoutJob.perform_now(client_id: "client", logout_uri: logout_uri, subject: "subject", sid: "sid")
  end
end
