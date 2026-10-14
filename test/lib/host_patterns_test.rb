require "test_helper"
require "clinch/host_patterns"
require "clinch/internal_host_patterns"

# config.hosts wraps each pattern as \A#{pattern}(?::\d+)?\z, so a pattern
# that ends in its own \z can never match a host with a port. These go
# through Rails' own check rather than matching the patterns directly.
class HostPatternsTest < ActiveSupport::TestCase
  def allowed?(patterns, host)
    ActionDispatch::HostAuthorization::Permissions.new(patterns).allows?(host)
  end

  test "a subdomain on a non-default port is allowed" do
    assert allowed?([Clinch::HostPatterns.domain_and_subdomains("example.com")], "app.example.com:8443")
  end

  test "an internal address with a port is allowed" do
    assert allowed?(Clinch::InternalHostPatterns.all, "192.168.1.10:3000")
  end

  test "look-alikes are refused with or without a port" do
    domain = [Clinch::HostPatterns.domain_and_subdomains("example.com")]
    %w[evil-example.com example.com.attacker.com evil-example.com:8443 example.com.attacker.com:443].each do |host|
      assert_not allowed?(domain, host), "#{host} should be refused"
    end

    %w[192.168.1.1.evil.com 192.168.1.1.evil.com:80].each do |host|
      assert_not allowed?(Clinch::InternalHostPatterns.all, host), "#{host} should be refused"
    end
  end
end
