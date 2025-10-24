class OidcJwtService
  class << self
    # Generate an ID token (JWT) for the user
    def generate_id_token(user, application, nonce: nil)
      now = Time.current.to_i

      payload = {
        iss: issuer_url,
        sub: user.id.to_s,
        aud: application.client_id,
        exp: now + 3600, # 1 hour
        iat: now,
        email: user.email_address,
        email_verified: true,
        preferred_username: user.email_address,
        name: user.email_address
      }

      # Add nonce if provided (OIDC requires this for implicit flow)
      payload[:nonce] = nonce if nonce.present?

      # Add groups if user has any
      if user.groups.any?
        payload[:groups] = user.groups.pluck(:name)
      end

      # Add admin claim if user is admin
      payload[:admin] = true if user.admin?

      # Add role-based claims if role mapping is enabled
      if application.role_mapping_enabled?
        add_role_claims!(payload, user, application)
      end

      JWT.encode(payload, private_key, "RS256", { kid: key_id, typ: "JWT" })
    end

    # Decode and verify an ID token
    def decode_id_token(token)
      JWT.decode(token, public_key, true, { algorithm: "RS256" })
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
      ENV.fetch("CLINCH_HOST", "http://localhost:3000")
    end

    private

    # Get or generate RSA private key
    def private_key
      @private_key ||= begin
        # Try ENV variable first (best for Docker/Kamal)
        if ENV["OIDC_PRIVATE_KEY"].present?
          OpenSSL::PKey::RSA.new(ENV["OIDC_PRIVATE_KEY"])
        # Then try Rails credentials
        elsif Rails.application.credentials.oidc_private_key.present?
          OpenSSL::PKey::RSA.new(Rails.application.credentials.oidc_private_key)
        else
          # Generate a new key for development
          # In production, you MUST set OIDC_PRIVATE_KEY env var or add to credentials
          Rails.logger.warn "OIDC: No private key found in ENV or credentials, generating new key (development only)"
          Rails.logger.warn "OIDC: Set OIDC_PRIVATE_KEY environment variable in production!"
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

    # Add role-based claims to the JWT payload
    def add_role_claims!(payload, user, application)
      user_roles = application.user_roles(user)
      return if user_roles.empty?

      role_names = user_roles.pluck(:name)

      # Filter roles by prefix if configured
      if application.role_prefix.present?
        role_names = role_names.select { |role| role.start_with?(application.role_prefix) }
      end

      return if role_names.empty?

      # Add roles using the configured claim name
      claim_name = application.role_claim_name.presence || 'roles'
      payload[claim_name] = role_names

      # Add role permissions if configured
      managed_permissions = application.parsed_managed_permissions
      if managed_permissions['include_permissions'] == true
        role_permissions = user_roles.map do |role|
          {
            name: role.name,
            display_name: role.display_name,
            permissions: role.permissions
          }
        end
        payload['role_permissions'] = role_permissions
      end

      # Add role metadata if configured
      if managed_permissions['include_metadata'] == true
        role_metadata = user_roles.map do |role|
          assignment = role.user_role_assignments.find_by(user: user)
          {
            name: role.name,
            source: assignment&.source,
            assigned_at: assignment&.created_at
          }
        end
        payload['role_metadata'] = role_metadata
      end
    end
  end
end
