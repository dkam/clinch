# CLINCH_HOST is this IdP's canonical external origin, e.g. https://auth.example.com.
# It anchors the OIDC issuer, the WebAuthn RP ID, and the forward-auth login
# redirect. In deployed (non-local) environments it MUST be set explicitly and
# never inferred from request headers — X-Forwarded-Host is attacker-influenceable,
# so inferring the origin from it would allow host-header phishing and open
# redirects. Fail fast at boot rather than start in an unsafe configuration.
#
# Skipped during asset precompilation (e.g. the Docker build step, which sets
# SECRET_KEY_BASE_DUMMY): no real CLINCH_HOST exists yet and assets don't need it.
unless Rails.env.local? || ENV["SECRET_KEY_BASE_DUMMY"].present?
  if ENV["CLINCH_HOST"].blank?
    raise "CLINCH_HOST must be set (e.g. https://auth.example.com). It is the " \
          "canonical origin of this Clinch instance and must not be inferred " \
          "from request headers."
  end
end
