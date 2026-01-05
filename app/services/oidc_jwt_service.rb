class OidcJwtService
  extend ClaimsMerger

  class << self
    # Generate an ID token (JWT) for the user
    def generate_id_token(user, application, consent: nil, nonce: nil, access_token: nil, auth_time: nil, acr: nil, scopes: "openid", claims_requests: {})
      now = Time.current.to_i
      # Use application's configured ID token TTL (defaults to 1 hour)
      ttl = application.id_token_expiry_seconds

      # Use pairwise SID from consent if available, fallback to user ID
      subject = consent&.sid || user.id.to_s

      # Parse scopes (space-separated string)
      requested_scopes = scopes.to_s.split

      # Parse claims_requests parameter for id_token context
      id_token_claims = claims_requests["id_token"] || {}

      # Required claims (always included per OIDC Core spec)
      payload = {
        iss: issuer_url,
        sub: subject,
        aud: application.client_id,
        exp: now + ttl,
        iat: now
      }

      # Email claims (only if 'email' scope requested AND either no claims filter OR email requested)
      if requested_scopes.include?("email")
        if should_include_claim?("email", id_token_claims)
          payload[:email] = user.email_address
        end
        if should_include_claim?("email_verified", id_token_claims)
          payload[:email_verified] = true
        end
      end

      # Profile claims (only if 'profile' scope requested)
      if requested_scopes.include?("profile")
        if should_include_claim?("preferred_username", id_token_claims)
          payload[:preferred_username] = user.username.presence || user.email_address
        end
        if should_include_claim?("name", id_token_claims)
          payload[:name] = user.name.presence || user.email_address
        end
        if should_include_claim?("updated_at", id_token_claims)
          payload[:updated_at] = user.updated_at.to_i
        end
      end

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

      # Groups claims (only if 'groups' scope requested AND requested in claims parameter)
      if requested_scopes.include?("groups") && user.groups.any?
        if should_include_claim?("groups", id_token_claims)
          payload[:groups] = user.groups.pluck(:name)
        end
      end

      # Merge custom claims from groups (arrays are combined, not overwritten)
      # Note: Custom claims from groups are always merged (not scope-dependent)
      user.groups.each do |group|
        payload = deep_merge_claims(payload, group.parsed_custom_claims)
      end

      # Merge custom claims from user (arrays are combined, other values override)
      payload = deep_merge_claims(payload, user.parsed_custom_claims)

      # Merge app-specific custom claims (highest priority, arrays are combined)
      payload = deep_merge_claims(payload, application.custom_claims_for_user(user))

      # Filter custom claims based on claims parameter
      # If claims parameter is present, only include requested custom claims
      if id_token_claims.any?
        payload = filter_custom_claims(payload, id_token_claims)
      end

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

    # Check if a claim should be included based on claims parameter
    # Returns true if:
    # - No claims parameter specified (include all scope-based claims)
    # - Claim is explicitly requested (even with null spec or essential: true)
    def should_include_claim?(claim_name, id_token_claims)
      # No claims parameter = include all scope-based claims
      return true if id_token_claims.empty?

      # Check if claim is requested
      return false unless id_token_claims.key?(claim_name)

      # Claim specification can be:
      # - null (requested)
      # - true (essential, requested)
      # - false (not requested)
      # - Hash with essential/value/values

      claim_spec = id_token_claims[claim_name]
      return true if claim_spec.nil? || claim_spec == true
      return false if claim_spec == false

      # If it's a hash, the claim is requested (filtering happens later)
      true if claim_spec.is_a?(Hash)
    end

    # Filter custom claims based on claims parameter
    # Removes claims not explicitly requested
    # Applies value/values filtering if specified
    def filter_custom_claims(payload, id_token_claims)
      # Get all claim names that are NOT standard OIDC claims
      standard_claims = %w[iss sub aud exp iat nbf jti nonce azp at_hash auth_time acr email email_verified name preferred_username updated_at groups]
      custom_claim_names = payload.keys.map(&:to_s) - standard_claims

      filtered = payload.dup

      custom_claim_names.each do |claim_name|
        claim_sym = claim_name.to_sym

        # If claim is not requested, remove it
        unless id_token_claims.key?(claim_name) || id_token_claims.key?(claim_sym)
          filtered.delete(claim_sym)
          next
        end

        # Apply value/values filtering if specified
        claim_spec = id_token_claims[claim_name] || id_token_claims[claim_sym]
        next unless claim_spec.is_a?(Hash)

        current_value = filtered[claim_sym]

        # Check value constraint
        if claim_spec["value"].present?
          filtered.delete(claim_sym) unless current_value == claim_spec["value"]
        end

        # Check values constraint (array of allowed values)
        if claim_spec["values"].is_a?(Array)
          filtered.delete(claim_sym) unless claim_spec["values"].include?(current_value)
        end
      end

      filtered
    end
  end
end
