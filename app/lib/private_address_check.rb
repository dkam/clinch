require "ipaddr"
require "resolv"

# SSRF guard for outbound requests to admin-configured URLs (currently the OIDC
# backchannel logout endpoint). Blocks hosts that are, or resolve to, private,
# loopback, link-local (incl. the cloud metadata address 169.254.169.254) or
# otherwise non-public address space.
module PrivateAddressCheck
  module_function

  # Hostnames that are internal by definition and must never be dialled.
  BLOCKED_HOSTNAMES = %w[localhost metadata.google.internal].freeze

  # Fast, DNS-free check: catches IP literals and well-known internal hostnames.
  # Suitable for model validation (deterministic, immediate admin feedback).
  def internal_host?(host)
    host = host.to_s.downcase
    return true if host.blank?
    return true if BLOCKED_HOSTNAMES.include?(host)
    return true if host.end_with?(".localhost")

    ip = parse_ip(host)
    ip ? internal_ip?(ip) : false
  end

  # Authoritative check for request time: the addresses to dial for `host`, or
  # nil if it is, or resolves to, anything internal. That also defeats a public
  # hostname pointed at an internal IP. Dial one of these rather than the
  # hostname, which would be resolved again and could get a different answer
  # (CLN-18). Empty when the host doesn't resolve.
  def public_addresses(host)
    return nil if internal_host?(host)

    resolved = addresses(host)
    resolved unless resolved.any? { |ip| internal_ip?(ip) }
  end

  def addresses(host)
    ip = parse_ip(host)
    return [ip] if ip

    Resolv.getaddresses(host.to_s).filter_map { |a| parse_ip(a) }
  rescue
    # Resolution failure: no addresses, so nothing a caller can dial.
    []
  end

  def internal_ip?(ip)
    ip.loopback? || ip.private? || ip.link_local? || unspecified?(ip)
  end

  def parse_ip(str)
    IPAddr.new(str.to_s)
  rescue IPAddr::Error
    nil
  end

  def unspecified?(ip)
    ip == IPAddr.new("0.0.0.0") || ip == IPAddr.new("::")
  end
end
