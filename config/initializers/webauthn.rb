# WebAuthn configuration for Clinch Identity Provider
WebAuthn.configure do |config|
  # The origin browsers report during a ceremony. CLINCH_HOST is documented
  # with a scheme, but the OIDC issuer and ForwardAuth have always accepted it
  # without one, so this does too. A bare host used to become the origin as it
  # was, which no browser ever reports, and the RP ID fell back to localhost.
  origin_host = ENV.fetch("CLINCH_HOST", "http://localhost").strip.chomp("/")
  unless origin_host.match?(%r{\Ahttps?://}i)
    origin_host = "#{Rails.env.production? ? "https" : "http"}://#{origin_host}"
  end
  config.allowed_origins = [origin_host]
  origin_domain = URI.parse(origin_host).host.to_s.downcase

  # The RP ID is the domain that owns the passkeys: the origin's host or a
  # parent of it. By default it's the registrable domain (example.com for
  # auth.example.com), so passkeys survive moving Clinch to another subdomain.
  derived_rp_id = begin
    PublicSuffix.parse(origin_domain).domain || origin_domain
  rescue PublicSuffix::DomainInvalid
    origin_domain
  end

  # Browsers refuse an RP ID that isn't the origin's host or a parent of it,
  # such as the localhost that .env.example used to preset, so no passkey can
  # exist under one. Using the derived RP ID instead loses nothing.
  configured_rp_id = ENV["CLINCH_RP_ID"].to_s.strip.downcase.presence
  config.rp_id = if configured_rp_id.nil?
    derived_rp_id
  elsif origin_domain == configured_rp_id || origin_domain.end_with?(".#{configured_rp_id}")
    configured_rp_id
  else
    Rails.logger.error "WebAuthn: CLINCH_RP_ID '#{configured_rp_id}' can't own passkeys for #{origin_host}; using '#{derived_rp_id}'"
    derived_rp_id
  end

  # For development, we also allow localhost with common ports and without port
  if Rails.env.development?
    config.allowed_origins += [
      "http://localhost",
      "http://localhost:3000",
      "http://localhost:3035",
      "http://127.0.0.1",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3035"
    ]
  end

  # Relying Party name shown in authenticator prompts
  config.rp_name = ENV.fetch("CLINCH_RP_NAME", "Clinch Identity Provider")

  # Credential timeout in milliseconds (60 seconds)
  # Users have 60 seconds to complete the authentication ceremony
  config.credential_options_timeout = 60_000

  # Supported algorithms for credential creation
  # ES256: ECDSA with P-256 and SHA-256 (most common, secure)
  # RS256: RSASSA-PKCS1-v1_5 with SHA-256 (hardware keys often use this)
  config.algorithms = ["ES256", "RS256"]

  # Encoding for credential IDs and other data
  config.encoding = :base64url

  # Custom verifier for additional security checks if needed
  # config.verifier = MyCustomVerifier.new
end

# Security note: WebAuthn requires HTTPS in production
# The WebAuthn API will not work on non-secure origins in production browsers
# Ensure CLINCH_HOST uses https:// in production environments

# Example environment variables:
# CLINCH_HOST=https://auth.example.com
# CLINCH_RP_ID=example.com
# CLINCH_RP_NAME="Example Company Identity Provider"
# CLINCH_WEBAUTHN_ATTESTATION=none
# CLINCH_WEBAUTHN_USER_VERIFICATION=preferred
# CLINCH_WEBAUTHN_RESIDENT_KEY=preferred
