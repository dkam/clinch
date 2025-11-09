class OidcController < ApplicationController
  # Discovery and JWKS endpoints are public
  allow_unauthenticated_access only: [:discovery, :jwks, :token, :userinfo, :logout]
  skip_before_action :verify_authenticity_token, only: [:token, :logout]

  # GET /.well-known/openid-configuration
  def discovery
    base_url = OidcJwtService.issuer_url

    config = {
      issuer: base_url,
      authorization_endpoint: "#{base_url}/oauth/authorize",
      token_endpoint: "#{base_url}/oauth/token",
      userinfo_endpoint: "#{base_url}/oauth/userinfo",
      jwks_uri: "#{base_url}/.well-known/jwks.json",
      end_session_endpoint: "#{base_url}/logout",
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email", "groups"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: ["sub", "email", "email_verified", "name", "preferred_username", "groups", "admin"],
      code_challenge_methods_supported: ["plain", "S256"]
    }

    render json: config
  end

  # GET /.well-known/jwks.json
  def jwks
    render json: OidcJwtService.jwks
  end

  # GET /oauth/authorize
  def authorize
    # Get parameters
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
      render plain: "Invalid request: missing required parameters", status: :bad_request
      return
    end

    # Validate PKCE parameters if present
    if code_challenge.present?
      unless %w[plain S256].include?(code_challenge_method)
        render plain: "Invalid code_challenge_method. Supported: plain, S256", status: :bad_request
        return
      end

      # Validate code challenge format (base64url-encoded, 43-128 characters)
      unless code_challenge.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
        render plain: "Invalid code_challenge format. Must be 43-128 characters of base64url encoding", status: :bad_request
        return
      end
    end

    # Find the application
    @application = Application.find_by(client_id: client_id, app_type: "oidc")
    unless @application
      render plain: "Invalid client_id", status: :bad_request
      return
    end

    # Validate redirect URI
    unless @application.parsed_redirect_uris.include?(redirect_uri)
      render plain: "Invalid redirect_uri", status: :bad_request
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

    # Render consent page
    @redirect_uri = redirect_uri
    @scopes = requested_scopes
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

    unless grant_type == "authorization_code"
      render json: { error: "unsupported_grant_type" }, status: :bad_request
      return
    end

    # Get client credentials from Authorization header or params
    client_id, client_secret = extract_client_credentials

    unless client_id && client_secret
      render json: { error: "invalid_client" }, status: :unauthorized
      return
    end

    # Find and validate the application
    application = Application.find_by(client_id: client_id)
    unless application && application.authenticate_client_secret(client_secret)
      render json: { error: "invalid_client" }, status: :unauthorized
      return
    end

    # Get the authorization code
    code = params[:code]
    redirect_uri = params[:redirect_uri]
    code_verifier = params[:code_verifier]

    auth_code = OidcAuthorizationCode.find_by(
      application: application,
      code: code,
      used: false
    )

    unless auth_code
      render json: { error: "invalid_grant" }, status: :bad_request
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

    # Validate PKCE if code challenge is present
    unless validate_pkce(auth_code, code_verifier)
      return
    end

    # Mark code as used
    auth_code.update!(used: true)

    # Get the user
    user = auth_code.user

    # Generate access token
    access_token = SecureRandom.urlsafe_base64(32)
    OidcAccessToken.create!(
      application: application,
      user: user,
      token: access_token,
      scope: auth_code.scope,
      expires_at: 1.hour.from_now
    )

    # Generate ID token
    id_token = OidcJwtService.generate_id_token(user, application, nonce: auth_code.nonce)

    # Return tokens
    render json: {
      access_token: access_token,
      token_type: "Bearer",
      expires_in: 3600,
      id_token: id_token,
      scope: auth_code.scope
    }
  end

  # GET /oauth/userinfo
  def userinfo
    # Extract access token from Authorization header
    auth_header = request.headers["Authorization"]
    unless auth_header&.start_with?("Bearer ")
      head :unauthorized
      return
    end

    access_token = auth_header.sub("Bearer ", "")

    # Find the access token
    token_record = OidcAccessToken.find_by(token: access_token)
    unless token_record
      head :unauthorized
      return
    end

    # Check if token is expired
    if token_record.expires_at < Time.current
      head :unauthorized
      return
    end

    # Get the user
    user = token_record.user

    # Return user claims
    claims = {
      sub: user.id.to_s,
      email: user.email_address,
      email_verified: true,
      preferred_username: user.email_address,
      name: user.name.presence || user.email_address
    }

    # Add groups if user has any
    if user.groups.any?
      claims[:groups] = user.groups.pluck(:name)
    end

    # Add admin claim if user is admin
    claims[:admin] = true if user.admin?

    # Merge custom claims from groups
    user.groups.each do |group|
      claims.merge!(group.parsed_custom_claims)
    end

    # Merge custom claims from user (overrides group claims)
    claims.merge!(user.parsed_custom_claims)

    render json: claims
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
      # Invalidate the current session
      Current.session&.destroy
      reset_session
    end

    # If post_logout_redirect_uri is provided, redirect there
    if post_logout_redirect_uri.present?
      redirect_uri = post_logout_redirect_uri
      redirect_uri += "?state=#{state}" if state.present?
      redirect_to redirect_uri, allow_other_host: true
    else
      # Default redirect to home page
      redirect_to root_path
    end
  end

  private

  def validate_pkce(auth_code, code_verifier)
    # Skip PKCE validation if no code challenge was stored (legacy clients)
    return true unless auth_code.code_challenge.present?

    # PKCE is required but no verifier provided
    unless code_verifier.present?
      render json: {
        error: "invalid_request",
        error_description: "code_verifier is required when code_challenge was provided"
      }, status: :bad_request
      return false
    end

    # Validate code verifier format (base64url-encoded, 43-128 characters)
    unless code_verifier.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
      render json: {
        error: "invalid_request",
        error_description: "Invalid code_verifier format. Must be 43-128 characters of base64url encoding"
      }, status: :bad_request
      return false
    end

    # Recreate code challenge based on method
    expected_challenge = case auth_code.code_challenge_method
                        when "plain"
                          code_verifier
                        when "S256"
                          Digest::SHA256.base64digest(code_verifier)
                            .tr("+/", "-_")
                            .tr("=", "")
                        else
                          render json: {
                            error: "server_error",
                            error_description: "Unsupported code challenge method"
                          }, status: :internal_server_error
                          return false
                        end

    # Validate the code challenge
    unless auth_code.code_challenge == expected_challenge
      render json: {
        error: "invalid_grant",
        error_description: "Invalid code verifier"
      }, status: :bad_request
      return false
    end

    true
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
end
