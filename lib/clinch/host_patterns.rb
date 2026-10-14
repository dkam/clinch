module Clinch
  # Host patterns for `config.hosts` built from CLINCH_HOST. See also
  # Clinch::InternalHostPatterns.
  module HostPatterns
    # config.hosts wraps each pattern as \A#{pattern}(?::\d+)?\z, but a pattern
    # that ends in its own \z leaves that port suffix nothing to match, so
    # patterns allow the port themselves.
    PORT = /(?::\d+)?/

    # The registrable domain and any subdomain of it, on any port. Anchored,
    # with a mandatory dot before the domain, so look-alikes such as
    # "evil-example.com" or "example.com.attacker.com" do NOT match; an
    # unanchored /.*example\.com/ would allow both.
    def self.domain_and_subdomains(domain)
      /\A(.+\.)?#{Regexp.escape(domain)}#{PORT}\z/i
    end
  end
end
