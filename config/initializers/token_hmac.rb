# Token HMAC key derivation
# This key is used to compute HMAC-based token prefixes for fast lookup
# Derived from SECRET_KEY_BASE - no storage needed, deterministic output
module TokenHmac
  KEY = Rails.application.key_generator.generate_key('oidc_token_prefix', 32)
end
