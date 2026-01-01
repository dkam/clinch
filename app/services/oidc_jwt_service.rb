class OidcJwtService
  extend ClaimsMerger

  class << self
    # Generate an ID token (JWT) for the user
    def generate_id_token(user, application, consent: nil, nonce: nil, access_token: nil, auth_time: nil, acr: nil)
      now = Time.current.to_i
      # Use application's configured ID token TTL (defaults to 1 hour)
      ttl = application.id_token_expiry_seconds

      # Use pairwise SID from consent if available, fallback to user ID
      subject = consent&.sid || user.id.to_s

      payload = {
        iss: issuer_url,
        sub: subject,
        aud: application.client_id,
        exp: now + ttl,
        iat: now,
        email: user.email_address,
        email_verified: true,
        preferred_username: user.username.presence || user.email_address,
        name: user.name.presence || user.email_address
      }

      # Add nonce if provided (OIDC requires this for implicit flow)
      payload[:nonce] = nonce if nonce.present?

      # Add auth_time if provided (OIDC Core §2 - required when max_age is used)
      payload[:auth_time] = auth_time if auth_time.present?

      # Add acr if provided (OIDC Core §2 - authentication context class reference)
      payload[:acr] = acr if acr.present?

      # Add azp (authorized party) - the client_id this token was issued to
      # OIDC Core §2 - required when aud has multiple values, optional but useful for single
      payload[:azp] = application.client_id

      # Add at_hash if access token is provided (OIDC Core spec §3.1.3.6)
      # at_hash = left-most 128 bits of SHA-256 hash of access token, base64url encoded
      if access_token.present?
        sha256 = Digest::SHA256.digest(access_token)
        at_hash = Base64.urlsafe_encode64(sha256[0..15], padding: false)
        payload[:at_hash] = at_hash
      end

      # Add groups if user has any
      if user.groups.any?
        payload[:groups] = user.groups.pluck(:name)
      end

      # Merge custom claims from groups (arrays are combined, not overwritten)
      user.groups.each do |group|
        payload = deep_merge_claims(payload, group.parsed_custom_claims)
      end

      # Merge custom claims from user (arrays are combined, other values override)
      payload = deep_merge_claims(payload, user.parsed_custom_claims)

      # Merge app-specific custom claims (highest priority, arrays are combined)
      payload = deep_merge_claims(payload, application.custom_claims_for_user(user))

      JWT.encode(payload, private_key, "RS256", {kid: key_id, typ: "JWT"})
    end

    # Generate a backchannel logout token (JWT)
    # Per OIDC Back-Channel Logout spec, this token:
    # - MUST include iss, aud, iat, jti, events claims
    # - MUST include sub or sid (or both) - we always include both
    # - MUST NOT include nonce claim
    def generate_logout_token(user, application, consent)
      now = Time.current.to_i

      payload = {
        iss: issuer_url,
        sub: consent.sid,  # Pairwise subject identifier
        aud: application.client_id,
        iat: now,
        jti: SecureRandom.uuid,  # Unique identifier for this logout token
        sid: consent.sid,  # Session ID - always included for granular logout
        events: {
          "http://schemas.openid.net/event/backchannel-logout" => {}
        }
      }

      # Important: Do NOT include nonce in logout tokens (spec requirement)
      JWT.encode(payload, private_key, "RS256", {kid: key_id, typ: "JWT"})
    end

    # Decode and verify an ID token
    def decode_id_token(token)
      JWT.decode(token, public_key, true, {algorithm: "RS256"})
    end

    # Get the public key in JWK format for the JWKS endpoint
    def jwks
      {
        keys: [
          {
            kty: "RSA",
            kid: key_id,
            use: "sig",
            alg: "RS256",
            n: Base64.urlsafe_encode64(public_key.n.to_s(2), padding: false),
            e: Base64.urlsafe_encode64(public_key.e.to_s(2), padding: false)
          }
        ]
      }
    end

    # Get the issuer URL (base URL of this OIDC provider)
    def issuer_url
      # In production, this should come from ENV or config
      # For now, we'll use a placeholder that can be overridden
      host = ENV.fetch("CLINCH_HOST", "localhost:3000")
      # Ensure URL has protocol - use https:// in production, http:// in development
      if host.match?(/^https?:\/\//)
        host
      else
        protocol = Rails.env.production? ? "https" : "http"
        "#{protocol}://#{host}"
      end
    end

    private

    # Get or generate RSA private key
    def private_key
      @private_key ||= begin
        key_source = nil

        # Try ENV variable first (best for Docker/Kamal)
        if ENV["OIDC_PRIVATE_KEY"].present?
          key_source = ENV["OIDC_PRIVATE_KEY"]
        # Then try Rails credentials
        elsif Rails.application.credentials.oidc_private_key.present?
          key_source = Rails.application.credentials.oidc_private_key
        end

        if key_source.present?
          begin
            # Handle both actual newlines and escaped \n sequences
            # Some .env loaders may escape newlines, so we need to convert them back
            key_data = key_source.gsub("\\n", "\n")
            OpenSSL::PKey::RSA.new(key_data)
          rescue OpenSSL::PKey::RSAError => e
            Rails.logger.error "OIDC: Failed to load private key: #{e.message}"
            Rails.logger.error "OIDC: Key source length: #{key_source.length}, starts with: #{key_source[0..50]}"
            raise "Invalid OIDC private key format. Please ensure the key is in PEM format with proper newlines."
          end
        else
          # In production, we should never generate a key on the fly
          # because it would be different across servers/deployments
          if Rails.env.production?
            raise "OIDC private key not configured. Set OIDC_PRIVATE_KEY environment variable or add to Rails credentials."
          end

          # Generate a new key for development/test only
          Rails.logger.warn "OIDC: No private key found in ENV or credentials, generating new key (development only)"
          Rails.logger.warn "OIDC: Set OIDC_PRIVATE_KEY environment variable for consistency across restarts"
          OpenSSL::PKey::RSA.new(2048)
        end
      end
    end

    # Get the corresponding public key
    def public_key
      @public_key ||= private_key.public_key
    end

    # Key identifier (fingerprint of the public key)
    def key_id
      @key_id ||= Digest::SHA256.hexdigest(public_key.to_pem)[0..15]
    end
  end
end
