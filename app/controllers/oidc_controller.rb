class OidcController < ApplicationController
  # Discovery and JWKS endpoints are public
  allow_unauthenticated_access only: [:discovery, :jwks, :token, :revoke, :userinfo, :logout]
  skip_before_action :verify_authenticity_token, only: [:token, :revoke, :logout]

  # Rate limiting to prevent brute force and abuse
  rate_limit to: 60, within: 1.minute, only: [:token, :revoke], with: -> {
    render json: { error: "too_many_requests", error_description: "Rate limit exceeded. Try again later." }, status: :too_many_requests
  }
  rate_limit to: 30, within: 1.minute, only: [:authorize, :consent], with: -> {
    render plain: "Too many authorization attempts. Try again later.", status: :too_many_requests
  }

  # GET /.well-known/openid-configuration
  def discovery
    base_url = OidcJwtService.issuer_url

    config = {
      issuer: base_url,
      authorization_endpoint: "#{base_url}/oauth/authorize",
      token_endpoint: "#{base_url}/oauth/token",
      revocation_endpoint: "#{base_url}/oauth/revoke",
      userinfo_endpoint: "#{base_url}/oauth/userinfo",
      jwks_uri: "#{base_url}/.well-known/jwks.json",
      end_session_endpoint: "#{base_url}/logout",
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email", "groups", "offline_access"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: ["sub", "email", "email_verified", "name", "preferred_username", "groups", "admin"],
      code_challenge_methods_supported: ["plain", "S256"],
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true
    }

    render json: config
  end

  # GET /.well-known/jwks.json
  def jwks
    render json: OidcJwtService.jwks
  end

  # GET /oauth/authorize
  def authorize
    # Get parameters (ignore forward auth tokens and other unknown params)
    client_id = params[:client_id]
    redirect_uri = params[:redirect_uri]
    state = params[:state]
    nonce = params[:nonce]
    scope = params[:scope] || "openid"
    response_type = params[:response_type]
    code_challenge = params[:code_challenge]
    code_challenge_method = params[:code_challenge_method] || "plain"

    # Validate required parameters
    unless client_id.present? && redirect_uri.present? && response_type == "code"
      error_details = []
      error_details << "client_id is required" unless client_id.present?
      error_details << "redirect_uri is required" unless redirect_uri.present?
      error_details << "response_type must be 'code'" unless response_type == "code"

      render plain: "Invalid request: #{error_details.join(', ')}", status: :bad_request
      return
    end

    # Validate PKCE parameters if present
    if code_challenge.present?
      unless %w[plain S256].include?(code_challenge_method)
        render plain: "Invalid code_challenge_method: must be 'plain' or 'S256'", status: :bad_request
        return
      end

      # Validate code challenge format (base64url-encoded, 43-128 characters)
      unless code_challenge.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
        render plain: "Invalid code_challenge format: must be 43-128 characters of base64url encoding", status: :bad_request
        return
      end
    end

    # Find the application
    @application = Application.find_by(client_id: client_id, app_type: "oidc")
    unless @application
      # Log all OIDC applications for debugging
      all_oidc_apps = Application.where(app_type: "oidc")
      Rails.logger.error "OAuth: Invalid request - application not found for client_id: #{client_id}"
      Rails.logger.error "OAuth: Available OIDC applications: #{all_oidc_apps.pluck(:id, :client_id, :name)}"

      error_msg = if Rails.env.development?
        "Invalid request: Application not found for client_id '#{client_id}'. Available OIDC applications: #{all_oidc_apps.pluck(:name, :client_id).map { |name, id| "#{name} (#{id})" }.join(', ')}"
      else
        "Invalid request: Application not found"
      end

      render plain: error_msg, status: :bad_request
      return
    end

    # Validate redirect URI first (required before we can safely redirect with errors)
    unless @application.parsed_redirect_uris.include?(redirect_uri)
      Rails.logger.error "OAuth: Invalid request - redirect URI mismatch. Expected: #{@application.parsed_redirect_uris}, Got: #{redirect_uri}"

      # For development, show detailed error
      error_msg = if Rails.env.development?
        "Invalid request: Redirect URI mismatch. Application is configured for: #{@application.parsed_redirect_uris.join(', ')}, but received: #{redirect_uri}"
      else
        "Invalid request: Redirect URI not registered for this application"
      end

      render plain: error_msg, status: :bad_request
      return
    end

    # Check if application is active (now we can safely redirect with error)
    unless @application.active?
      Rails.logger.error "OAuth: Application is not active: #{@application.name}"
      error_uri = "#{redirect_uri}?error=unauthorized_client&error_description=Application+is+not+active"
      error_uri += "&state=#{CGI.escape(state)}" if state.present?
      redirect_to error_uri, allow_other_host: true
      return
    end

    # Check if user is authenticated
    unless authenticated?
      # Store OAuth parameters in session and redirect to sign in
      session[:oauth_params] = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        state: state,
        nonce: nonce,
        scope: scope,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      }
      redirect_to signin_path, alert: "Please sign in to continue"
      return
    end

    # Get the authenticated user
    user = Current.session.user

    # Check if user is allowed to access this application
    unless @application.user_allowed?(user)
      render plain: "You do not have permission to access this application", status: :forbidden
      return
    end

    requested_scopes = scope.split(" ")

    # Check if user has already granted consent for these scopes
    existing_consent = user.has_oidc_consent?(@application, requested_scopes)
    if existing_consent
      # User has already consented, generate authorization code directly
      code = SecureRandom.urlsafe_base64(32)
      auth_code = OidcAuthorizationCode.create!(
        application: @application,
        user: user,
        code: code,
        redirect_uri: redirect_uri,
        scope: scope,
        nonce: nonce,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
        expires_at: 10.minutes.from_now
      )

      # Redirect back to client with authorization code
      redirect_uri = "#{redirect_uri}?code=#{code}"
      redirect_uri += "&state=#{state}" if state.present?
      redirect_to redirect_uri, allow_other_host: true
      return
    end

    # Store OAuth parameters for consent page
    session[:oauth_params] = {
      client_id: client_id,
      redirect_uri: redirect_uri,
      state: state,
      nonce: nonce,
      scope: scope,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method
    }

    # Render consent page with dynamic CSP for OAuth redirect
    @redirect_uri = redirect_uri
    @scopes = requested_scopes

    # Add the redirect URI to CSP form-action for this specific request
    # This allows the OAuth redirect to work while maintaining security
    # CSP must allow the OAuth client's redirect_uri as a form submission target
    if redirect_uri.present?
      begin
        redirect_host = URI.parse(redirect_uri).host
        csp = request.content_security_policy
        if csp && redirect_host
          # Only modify if form_action is available and mutable
          if csp.respond_to?(:form_action) && csp.form_action.respond_to?(:<<)
            csp.form_action << "https://#{redirect_host}"
          end
        end
      rescue => e
        # Log CSP modification errors but don't fail the request
        Rails.logger.warn "OAuth: Could not modify CSP for redirect_uri #{redirect_uri}: #{e.message}"
      end
    end

    render :consent
  end

  # POST /oauth/authorize/consent
  def consent
    # Get OAuth params from session
    oauth_params = session[:oauth_params]
    unless oauth_params
      redirect_to root_path, alert: "Session expired. Please try again."
      return
    end

    # User denied consent
    if params[:deny].present?
      session.delete(:oauth_params)
      error_uri = "#{oauth_params['redirect_uri']}?error=access_denied"
      error_uri += "&state=#{oauth_params['state']}" if oauth_params['state']
      redirect_to error_uri, allow_other_host: true
      return
    end

    # Find the application
    client_id = oauth_params['client_id']
    application = Application.find_by(client_id: client_id, app_type: "oidc")

    # Check if application is active (redirect with OAuth error)
    unless application&.active?
      Rails.logger.error "OAuth: Application is not active: #{application&.name || client_id}"
      session.delete(:oauth_params)
      error_uri = "#{oauth_params['redirect_uri']}?error=unauthorized_client&error_description=Application+is+not+active"
      error_uri += "&state=#{CGI.escape(oauth_params['state'])}" if oauth_params['state'].present?
      redirect_to error_uri, allow_other_host: true
      return
    end

    user = Current.session.user

    # Record user consent
    requested_scopes = oauth_params['scope'].split(' ')
    OidcUserConsent.upsert(
      {
        user_id: user.id,
        application_id: application.id,
        scopes_granted: requested_scopes.join(' '),
        granted_at: Time.current
      },
      unique_by: [:user_id, :application_id]
    )

    # Generate authorization code
    code = SecureRandom.urlsafe_base64(32)
    auth_code = OidcAuthorizationCode.create!(
      application: application,
      user: user,
      code: code,
      redirect_uri: oauth_params['redirect_uri'],
      scope: oauth_params['scope'],
      nonce: oauth_params['nonce'],
      code_challenge: oauth_params['code_challenge'],
      code_challenge_method: oauth_params['code_challenge_method'],
      expires_at: 10.minutes.from_now
    )

    # Clear OAuth params from session
    session.delete(:oauth_params)

    # Redirect back to client with authorization code
    redirect_uri = "#{oauth_params['redirect_uri']}?code=#{code}"
    redirect_uri += "&state=#{oauth_params['state']}" if oauth_params['state']

    redirect_to redirect_uri, allow_other_host: true
  end

  # POST /oauth/token
  def token
    grant_type = params[:grant_type]

    case grant_type
    when "authorization_code"
      handle_authorization_code_grant
    when "refresh_token"
      handle_refresh_token_grant
    else
      render json: { error: "unsupported_grant_type" }, status: :bad_request
    end
  end

  def handle_authorization_code_grant
    # Get client credentials from Authorization header or params
    client_id, client_secret = extract_client_credentials

    unless client_id
      render json: { error: "invalid_client", error_description: "client_id is required" }, status: :unauthorized
      return
    end

    # Find the application
    application = Application.find_by(client_id: client_id)
    unless application
      render json: { error: "invalid_client", error_description: "Unknown client" }, status: :unauthorized
      return
    end

    # Validate client credentials based on client type
    if application.public_client?
      # Public clients don't have a secret - they MUST use PKCE (checked later)
      Rails.logger.info "OAuth: Public client authentication for #{application.name}"
    else
      # Confidential clients MUST provide valid client_secret
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: { error: "invalid_client", error_description: "Invalid client credentials" }, status: :unauthorized
        return
      end
    end

    # Check if application is active
    unless application.active?
      Rails.logger.error "OAuth: Token request for inactive application: #{application.name}"
      render json: { error: "invalid_client", error_description: "Application is not active" }, status: :forbidden
      return
    end

    # Get the authorization code
    code = params[:code]
    redirect_uri = params[:redirect_uri]
    code_verifier = params[:code_verifier]

    auth_code = OidcAuthorizationCode.find_by(
      application: application,
      code: code
    )

    unless auth_code
      render json: { error: "invalid_grant" }, status: :bad_request
      return
    end

    # Use a transaction with pessimistic locking to prevent code reuse
    begin
      OidcAuthorizationCode.transaction do
        # Lock the record to prevent concurrent access
        auth_code.lock!

        # Check if code has already been used (CRITICAL: check AFTER locking)
        if auth_code.used?
          # Per OAuth 2.0 spec, if an auth code is reused, revoke all tokens issued from it
          Rails.logger.warn "OAuth Security: Authorization code reuse detected for code #{auth_code.id}"

          # Revoke all access tokens issued from this authorization code
          OidcAccessToken.where(
            application: application,
            user: auth_code.user,
            created_at: auth_code.created_at..Time.current
          ).update_all(expires_at: Time.current)

          render json: {
            error: "invalid_grant",
            error_description: "Authorization code has already been used"
          }, status: :bad_request
          return
        end

        # Check if code is expired
        if auth_code.expires_at < Time.current
          render json: { error: "invalid_grant", error_description: "Authorization code expired" }, status: :bad_request
          return
        end

        # Validate redirect URI matches
        unless auth_code.redirect_uri == redirect_uri
          render json: { error: "invalid_grant", error_description: "Redirect URI mismatch" }, status: :bad_request
          return
        end

        # Validate PKCE - required for public clients and optionally for confidential clients
        pkce_result = validate_pkce(application, auth_code, code_verifier)
        unless pkce_result[:valid]
          render json: {
            error: pkce_result[:error],
            error_description: pkce_result[:error_description]
          }, status: pkce_result[:status]
          return
        end

        # Mark code as used BEFORE generating tokens (prevents reuse)
        auth_code.update!(used: true)

        # Get the user
        user = auth_code.user

        # Generate access token record (opaque token with BCrypt hashing)
        access_token_record = OidcAccessToken.create!(
          application: application,
          user: user,
          scope: auth_code.scope
        )

        # Generate refresh token (opaque, with hashing)
        refresh_token_record = OidcRefreshToken.create!(
          application: application,
          user: user,
          oidc_access_token: access_token_record,
          scope: auth_code.scope
        )

        # Find user consent for this application
        consent = OidcUserConsent.find_by(user: user, application: application)

        unless consent
          Rails.logger.error "OIDC Security: Token requested without consent record (user: #{user.id}, app: #{application.id})"
          render json: { error: "invalid_grant", error_description: "Authorization consent not found" }, status: :bad_request
          return
        end

        # Generate ID token (JWT) with pairwise SID
        id_token = OidcJwtService.generate_id_token(user, application, consent: consent, nonce: auth_code.nonce)

        # Return tokens
        render json: {
          access_token: access_token_record.plaintext_token,  # Opaque token
          token_type: "Bearer",
          expires_in: application.access_token_ttl || 3600,
          id_token: id_token,  # JWT
          refresh_token: refresh_token_record.token,  # Opaque token
          scope: auth_code.scope
        }
      end
    rescue ActiveRecord::RecordNotFound
      render json: { error: "invalid_grant" }, status: :bad_request
    end
  end

  def handle_refresh_token_grant
    # Get client credentials from Authorization header or params
    client_id, client_secret = extract_client_credentials

    unless client_id
      render json: { error: "invalid_client", error_description: "client_id is required" }, status: :unauthorized
      return
    end

    # Find the application
    application = Application.find_by(client_id: client_id)
    unless application
      render json: { error: "invalid_client", error_description: "Unknown client" }, status: :unauthorized
      return
    end

    # Validate client credentials based on client type
    if application.public_client?
      # Public clients don't have a secret
      Rails.logger.info "OAuth: Public client refresh token request for #{application.name}"
    else
      # Confidential clients MUST provide valid client_secret
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: { error: "invalid_client", error_description: "Invalid client credentials" }, status: :unauthorized
        return
      end
    end

    # Check if application is active
    unless application.active?
      Rails.logger.error "OAuth: Refresh token request for inactive application: #{application.name}"
      render json: { error: "invalid_client", error_description: "Application is not active" }, status: :forbidden
      return
    end

    # Get the refresh token
    refresh_token = params[:refresh_token]
    unless refresh_token.present?
      render json: { error: "invalid_request", error_description: "refresh_token is required" }, status: :bad_request
      return
    end

    # Find the refresh token record
    # Note: This is inefficient with BCrypt hashing, but necessary for security
    # In production, consider adding a token prefix for faster lookup
    refresh_token_record = OidcRefreshToken.where(application: application).find do |rt|
      rt.token_matches?(refresh_token)
    end

    unless refresh_token_record
      render json: { error: "invalid_grant", error_description: "Invalid refresh token" }, status: :bad_request
      return
    end

    # Check if refresh token is expired
    if refresh_token_record.expired?
      render json: { error: "invalid_grant", error_description: "Refresh token expired" }, status: :bad_request
      return
    end

    # Check if refresh token is revoked
    if refresh_token_record.revoked?
      # If a revoked refresh token is used, it's a security issue
      # Revoke all tokens in the family (token rotation attack detection)
      Rails.logger.warn "OAuth Security: Revoked refresh token reuse detected for token family #{refresh_token_record.token_family_id}"
      refresh_token_record.revoke_family!

      render json: { error: "invalid_grant", error_description: "Refresh token has been revoked" }, status: :bad_request
      return
    end

    # Get the user
    user = refresh_token_record.user

    # Revoke the old refresh token (token rotation)
    refresh_token_record.revoke!

    # Generate new access token record (opaque token with BCrypt hashing)
    new_access_token = OidcAccessToken.create!(
      application: application,
      user: user,
      scope: refresh_token_record.scope
    )

    # Generate new refresh token (token rotation)
    new_refresh_token = OidcRefreshToken.create!(
      application: application,
      user: user,
      oidc_access_token: new_access_token,
      scope: refresh_token_record.scope,
      token_family_id: refresh_token_record.token_family_id  # Keep same family for rotation tracking
    )

    # Find user consent for this application
    consent = OidcUserConsent.find_by(user: user, application: application)

    unless consent
      Rails.logger.error "OIDC Security: Refresh token used without consent record (user: #{user.id}, app: #{application.id})"
      render json: { error: "invalid_grant", error_description: "Authorization consent not found" }, status: :bad_request
      return
    end

    # Generate new ID token (JWT with pairwise SID, no nonce for refresh grants)
    id_token = OidcJwtService.generate_id_token(user, application, consent: consent)

    # Return new tokens
    render json: {
      access_token: new_access_token.plaintext_token,  # Opaque token
      token_type: "Bearer",
      expires_in: application.access_token_ttl || 3600,
      id_token: id_token,  # JWT
      refresh_token: new_refresh_token.token,  # Opaque token
      scope: refresh_token_record.scope
    }
  rescue ActiveRecord::RecordNotFound
    render json: { error: "invalid_grant" }, status: :bad_request
  end

  # GET /oauth/userinfo
  def userinfo
    # Extract access token from Authorization header
    auth_header = request.headers["Authorization"]
    unless auth_header&.start_with?("Bearer ")
      head :unauthorized
      return
    end

    token = auth_header.sub("Bearer ", "")

    # Find and validate access token (opaque token with BCrypt hashing)
    access_token = OidcAccessToken.find_by_token(token)
    unless access_token&.active?
      head :unauthorized
      return
    end

    # Check if application is active (immediate cutoff when app is disabled)
    unless access_token.application&.active?
      Rails.logger.warn "OAuth: Userinfo request for inactive application: #{access_token.application&.name}"
      head :forbidden
      return
    end

    # Get the user (with fresh data from database)
    user = access_token.user
    unless user
      head :unauthorized
      return
    end

    # Find user consent for this application to get pairwise SID
    consent = OidcUserConsent.find_by(user: user, application: access_token.application)
    subject = consent&.sid || user.id.to_s

    # Return user claims
    claims = {
      sub: subject,
      email: user.email_address,
      email_verified: true,
      preferred_username: user.email_address,
      name: user.name.presence || user.email_address
    }

    # Add groups if user has any
    if user.groups.any?
      claims[:groups] = user.groups.pluck(:name)
    end

    # Merge custom claims from groups
    user.groups.each do |group|
      claims.merge!(group.parsed_custom_claims)
    end

    # Merge custom claims from user (overrides group claims)
    claims.merge!(user.parsed_custom_claims)

    # Merge app-specific custom claims (highest priority)
    application = access_token.application
    claims.merge!(application.custom_claims_for_user(user))

    render json: claims
  end

  # POST /oauth/revoke
  # RFC 7009 - Token Revocation
  def revoke
    # Get client credentials
    client_id, client_secret = extract_client_credentials

    unless client_id && client_secret
      # RFC 7009 says we should return 200 OK even for invalid client
      # But log the attempt for security monitoring
      Rails.logger.warn "OAuth: Token revocation attempted with invalid client credentials"
      head :ok
      return
    end

    # Find and validate the application
    application = Application.find_by(client_id: client_id)
    unless application && application.authenticate_client_secret(client_secret)
      Rails.logger.warn "OAuth: Token revocation attempted for invalid application: #{client_id}"
      head :ok
      return
    end

    # Check if application is active (RFC 7009: still return 200 OK for privacy)
    unless application.active?
      Rails.logger.warn "OAuth: Token revocation attempted for inactive application: #{application.name}"
      head :ok
      return
    end

    # Get the token to revoke
    token = params[:token]
    token_type_hint = params[:token_type_hint]  # Optional hint: "access_token" or "refresh_token"

    unless token.present?
      # RFC 7009: Missing token parameter is an error
      render json: { error: "invalid_request", error_description: "token parameter is required" }, status: :bad_request
      return
    end

    # Try to find and revoke the token
    # Check token type hint first for efficiency, otherwise try both
    revoked = false

    if token_type_hint == "refresh_token" || token_type_hint.nil?
      # Try to find as refresh token
      refresh_token_record = OidcRefreshToken.where(application: application).find do |rt|
        rt.token_matches?(token)
      end

      if refresh_token_record
        refresh_token_record.revoke!
        Rails.logger.info "OAuth: Refresh token revoked for application #{application.name}"
        revoked = true
      end
    end

    if !revoked && (token_type_hint == "access_token" || token_type_hint.nil?)
      # Try to find as access token
      access_token_record = OidcAccessToken.where(application: application).find do |at|
        at.token_matches?(token)
      end

      if access_token_record
        access_token_record.revoke!
        Rails.logger.info "OAuth: Access token revoked for application #{application.name}"
        revoked = true
      end
    end

    # RFC 7009: Always return 200 OK, even if token was not found
    # This prevents token scanning attacks
    head :ok
  end

  # GET /logout
  def logout
    # OpenID Connect RP-Initiated Logout
    # Handle id_token_hint and post_logout_redirect_uri parameters

    id_token_hint = params[:id_token_hint]
    post_logout_redirect_uri = params[:post_logout_redirect_uri]
    state = params[:state]

    # If user is authenticated, log them out
    if authenticated?
      user = Current.session.user

      # Send backchannel logout notifications to all connected applications
      send_backchannel_logout_notifications(user)

      # Invalidate the current session
      Current.session&.destroy
      reset_session
    end

    # If post_logout_redirect_uri is provided, validate and redirect
    if post_logout_redirect_uri.present?
      validated_uri = validate_logout_redirect_uri(post_logout_redirect_uri)

      if validated_uri
        redirect_uri = validated_uri
        redirect_uri += "?state=#{state}" if state.present?
        redirect_to redirect_uri, allow_other_host: true
      else
        # Invalid redirect URI - log warning and go to default
        Rails.logger.warn "OIDC Logout: Invalid post_logout_redirect_uri attempted: #{post_logout_redirect_uri}"
        redirect_to root_path
      end
    else
      # Default redirect to home page
      redirect_to root_path
    end
  end

  private

  def validate_pkce(application, auth_code, code_verifier)
    # Check if PKCE is required for this application
    pkce_required = application.requires_pkce?
    pkce_provided = auth_code.code_challenge.present?

    # If PKCE is required but wasn't provided during authorization
    if pkce_required && !pkce_provided
      client_type = application.public_client? ? "public clients" : "this application"
      return {
        valid: false,
        error: "invalid_request",
        error_description: "PKCE is required for #{client_type}. code_challenge must be provided during authorization.",
        status: :bad_request
      }
    end

    # Skip validation if no code challenge was stored (legacy clients without PKCE requirement)
    return { valid: true } unless pkce_provided

    # PKCE was provided during authorization but no verifier sent with token request
    unless code_verifier.present?
      return {
        valid: false,
        error: "invalid_request",
        error_description: "code_verifier is required when code_challenge was provided",
        status: :bad_request
      }
    end

    # Validate code verifier format (base64url-encoded, 43-128 characters)
    unless code_verifier.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
      return {
        valid: false,
        error: "invalid_request",
        error_description: "Invalid code_verifier format. Must be 43-128 characters of base64url encoding",
        status: :bad_request
      }
    end

    # Recreate code challenge based on method
    expected_challenge = case auth_code.code_challenge_method
                        when "plain"
                          code_verifier
                        when "S256"
                          Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
                        else
                          return {
                            valid: false,
                            error: "server_error",
                            error_description: "Unsupported code challenge method",
                            status: :internal_server_error
                          }
                        end

    # Validate the code challenge
    unless auth_code.code_challenge == expected_challenge
      return {
        valid: false,
        error: "invalid_grant",
        error_description: "Invalid code verifier",
        status: :bad_request
      }
    end

    { valid: true }
  end

  def extract_client_credentials
    # Try Authorization header first (Basic auth)
    if request.headers["Authorization"]&.start_with?("Basic ")
      encoded = request.headers["Authorization"].sub("Basic ", "")
      decoded = Base64.decode64(encoded)
      decoded.split(":", 2)
    else
      # Fall back to POST parameters
      [params[:client_id], params[:client_secret]]
    end
  end

  def validate_logout_redirect_uri(uri)
    return nil unless uri.present?

    begin
      parsed_uri = URI.parse(uri)

      # Only allow HTTP/HTTPS schemes (prevent javascript:, data:, etc.)
      return nil unless parsed_uri.is_a?(URI::HTTP) || parsed_uri.is_a?(URI::HTTPS)

      # Only allow HTTPS in production
      return nil if Rails.env.production? && parsed_uri.scheme != 'https'

      # Check if URI matches any registered OIDC application's redirect URIs
      # According to OIDC spec, post_logout_redirect_uri should be pre-registered
      Application.oidc.active.find_each do |app|
        # Check if this URI matches any of the app's registered redirect URIs
        if app.parsed_redirect_uris.any? { |registered_uri| logout_uri_matches?(uri, registered_uri) }
          return uri
        end
      end

      # No matching application found
      nil
    rescue URI::InvalidURIError
      nil
    end
  end

  # Check if logout URI matches a registered redirect URI
  # More lenient than exact match - allows same host/path with different query params
  def logout_uri_matches?(provided, registered)
    # Exact match is always valid
    return true if provided == registered

    # Parse both URIs to compare components
    begin
      provided_parsed = URI.parse(provided)
      registered_parsed = URI.parse(registered)

      # Match if scheme, host, port, and path are the same
      # (allows different query params which is common for logout redirects)
      provided_parsed.scheme == registered_parsed.scheme &&
        provided_parsed.host == registered_parsed.host &&
        provided_parsed.port == registered_parsed.port &&
        provided_parsed.path == registered_parsed.path
    rescue URI::InvalidURIError
      false
    end
  end

  def send_backchannel_logout_notifications(user)
    # Find all active OIDC consents for this user
    consents = OidcUserConsent.where(user: user).includes(:application)

    consents.each do |consent|
      # Skip if application doesn't support backchannel logout
      next unless consent.application.supports_backchannel_logout?

      # Enqueue background job to send logout notification
      BackchannelLogoutJob.perform_later(
        user_id: user.id,
        application_id: consent.application.id,
        consent_sid: consent.sid
      )
    end

    Rails.logger.info "OidcController: Enqueued #{consents.count} backchannel logout notifications for user #{user.id}"
  rescue => e
    # Log error but don't block logout
    Rails.logger.error "OidcController: Failed to enqueue backchannel logout: #{e.class} - #{e.message}"
  end
end
