# Token HMAC key derivation
# This key is used to compute HMAC-based token prefixes for fast lookup
# Derived from SECRET_KEY_BASE - no storage needed, deterministic output
# Optional: Set OIDC_TOKEN_PREFIX_HMAC env var to override with explicit key
module TokenHmac
  KEY = ENV["OIDC_TOKEN_PREFIX_HMAC"] || Rails.application.key_generator.generate_key("oidc_token_prefix", 32)
end
