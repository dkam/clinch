module Clinch
  # Host patterns for RFC 1918 private ranges, added to `config.hosts` when
  # CLINCH_ALLOW_INTERNAL_IPS=true (cross-compose or host-networking deployments).
  #
  # These MUST be anchored. `config.hosts` regexes are matched with `===`, which
  # is unanchored, so a bare /192\.168\.\d+\.\d+/ also admits
  # "192.168.1.1.evil.com" — turning the DNS-rebinding defence into a no-op for
  # any attacker-controlled hostname that embeds a private address. The octets
  # are range-checked too, so "192.168.1.256" (a valid *hostname*, not an IP)
  # does not slip through.
  module InternalHostPatterns
    # 0-255, without allowing leading zeroes to pad an out-of-range value.
    OCTET = /(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/

    # 192.168.0.0/16
    CLASS_C = /\A192\.168\.#{OCTET}\.#{OCTET}\z/

    # 10.0.0.0/8
    CLASS_A = /\A10\.#{OCTET}\.#{OCTET}\.#{OCTET}\z/

    # 172.16.0.0/12
    CLASS_B = /\A172\.(?:1[6-9]|2\d|3[01])\.#{OCTET}\.#{OCTET}\z/

    def self.all
      [CLASS_C, CLASS_A, CLASS_B]
    end
  end
end
