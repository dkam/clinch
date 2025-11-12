# WebAuthn configuration for Clinch Identity Provider
WebAuthn.configure do |config|
  # Relying Party name (displayed in authenticator prompts)
  # CLINCH_HOST should include protocol (https://) for WebAuthn
  origin_host = ENV.fetch("CLINCH_HOST", "http://localhost")
  config.allowed_origins = [origin_host]

  # Relying Party ID (must match origin domain without protocol)
  # Extract domain from origin for RP ID if CLINCH_RP_ID not set
  if ENV["CLINCH_RP_ID"].present?
    config.rp_id = ENV["CLINCH_RP_ID"]
  else
    # Extract registrable domain from CLINCH_HOST using PublicSuffix
    origin_uri = URI.parse(origin_host)
    if origin_uri.host
      begin
        # Use PublicSuffix to get the registrable domain (e.g., "aapamilne.com" from "auth.aapamilne.com")
        domain = PublicSuffix.parse(origin_uri.host)
        config.rp_id = domain.domain || origin_uri.host
      rescue PublicSuffix::DomainInvalid => e
        Rails.logger.warn "WebAuthn: Failed to parse domain '#{origin_uri.host}': #{e.message}, using host as fallback"
        config.rp_id = origin_uri.host
      end
    else
      Rails.logger.error "WebAuthn: Could not extract host from CLINCH_HOST '#{origin_host}'"
      config.rp_id = "localhost"
    end
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