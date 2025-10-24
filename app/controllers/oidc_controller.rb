class OidcController < ApplicationController
  # Discovery and JWKS endpoints are public
  allow_unauthenticated_access only: [:discovery, :jwks, :token, :userinfo]
  skip_before_action :verify_authenticity_token, only: [:token]

  # GET /.well-known/openid-configuration
  def discovery
    base_url = OidcJwtService.issuer_url

    config = {
      issuer: base_url,
      authorization_endpoint: "#{base_url}/oauth/authorize",
      token_endpoint: "#{base_url}/oauth/token",
      userinfo_endpoint: "#{base_url}/oauth/userinfo",
      jwks_uri: "#{base_url}/.well-known/jwks.json",
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email", "groups"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: ["sub", "email", "email_verified", "name", "preferred_username", "groups", "admin"]
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

    # Validate required parameters
    unless client_id.present? && redirect_uri.present? && response_type == "code"
      render plain: "Invalid request: missing required parameters", status: :bad_request
      return
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
        scope: scope
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

    # Store OAuth parameters for consent page
    session[:oauth_params] = {
      client_id: client_id,
      redirect_uri: redirect_uri,
      state: state,
      nonce: nonce,
      scope: scope
    }

    # Render consent page
    @redirect_uri = redirect_uri
    @scopes = scope.split(" ")
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
      error_uri = "#{oauth_params[:redirect_uri]}?error=access_denied"
      error_uri += "&state=#{oauth_params[:state]}" if oauth_params[:state]
      redirect_to error_uri, allow_other_host: true
      return
    end

    # Find the application
    Rails.logger.debug "OAuth params: #{oauth_params.inspect}"
    application = Application.find_by(client_id: oauth_params[:client_id], app_type: "oidc")
    Rails.logger.debug "Found application: #{application.inspect}"
    user = Current.session.user

    # Generate authorization code
    code = SecureRandom.urlsafe_base64(32)
    auth_code = OidcAuthorizationCode.create!(
      application: application,
      user: user,
      code: code,
      redirect_uri: oauth_params[:redirect_uri],
      scope: oauth_params[:scope],
      expires_at: 10.minutes.from_now
    )

    # Store nonce in the authorization code metadata if needed
    # For now, we'll pass it through the code itself

    # Clear OAuth params from session
    session.delete(:oauth_params)

    # Redirect back to client with authorization code
    redirect_uri = "#{oauth_params[:redirect_uri]}?code=#{code}"
    redirect_uri += "&state=#{oauth_params[:state]}" if oauth_params[:state]

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
    id_token = OidcJwtService.generate_id_token(user, application)

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
      name: user.email_address
    }

    # Add groups if user has any
    if user.groups.any?
      claims[:groups] = user.groups.pluck(:name)
    end

    # Add admin claim if user is admin
    claims[:admin] = true if user.admin?

    render json: claims
  end

  private

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
