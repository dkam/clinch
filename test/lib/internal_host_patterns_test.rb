require "test_helper"
require "clinch/internal_host_patterns"

# Host authorisation is the DNS-rebinding defence. These patterns are added to
# config.hosts when CLINCH_ALLOW_INTERNAL_IPS=true, which .env.example documents
# as the normal setting, so an unanchored pattern silently allows any attacker
# host that merely *contains* a private-range address.
class InternalHostPatternsTest < ActiveSupport::TestCase
  def matches?(host)
    Clinch::InternalHostPatterns.all.any? { |p| p.match?(host) }
  end

  test "allows hosts that are exactly a private-range address" do
    %w[
      192.168.0.1 192.168.1.254 10.0.0.1 10.255.255.255
      172.16.0.1 172.20.10.5 172.31.255.254
    ].each do |host|
      assert matches?(host), "#{host} should be allowed"
    end
  end

  test "rejects attacker hosts that merely embed a private-range address" do
    %w[
      192.168.1.1.evil.com evil.com.10.0.0.1 172.16.0.1.attacker.test
      10.0.0.1.nip.io x192.168.1.1 192.168.1.1x
    ].each do |host|
      refute matches?(host), "#{host} must not be allowed"
    end
  end

  test "rejects public addresses and out-of-range octets" do
    %w[
      8.8.8.8 172.15.0.1 172.32.0.1 192.169.0.1 11.0.0.1
      192.168.1.256 192.168.999.1
    ].each do |host|
      refute matches?(host), "#{host} must not be allowed"
    end
  end
end
