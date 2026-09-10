class OidcController < ApplicationController
  # Grant types this authorization server supports. Single source of truth:
  # advertised in discovery (grant_types_supported), accepted at dynamic client
  # registration, and dispatched by the token endpoint. clinch offers all of these
  # to every OIDC client — they are all user-context grants gated by consent and
  # Application#user_allowed?, so there is no per-client grant restriction to
  # enforce. Keep this in sync with the `case grant_type` dispatch in #token.
  SUPPORTED_GRANT_TYPES = [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ].freeze

  # Discovery and JWKS endpoints are public
  # authorize is also unauthenticated to handle prompt=none and prompt=login specially
  allow_unauthenticated_access only: [:discovery, :jwks, :token, :revoke, :introspect, :userinfo, :logout, :authorize, :device_authorization]
  # Machine-to-machine endpoints (token/revoke/introspect/userinfo/device_authorization)
  # and pure redirect handlers (logout/authorize) legitimately skip CSRF. The consent
  # endpoint is browser-facing and state-changing (it grants OAuth scopes), so it MUST
  # keep CSRF protection — the consent form already embeds the token via form_with.
  skip_before_action :verify_authenticity_token, only: [:token, :revoke, :introspect, :userinfo, :logout, :authorize, :device_authorization]

  # RFC 6749 §4.1.2.1: client_id and redirect_uri must be validated *before* any
  # other error can be reported via redirect. Failures here render a plain page.
  before_action :set_application, only: :authorize
  before_action :validate_redirect_uri, only: :authorize

  # Rate limiting to prevent brute force and abuse.
  #
  # Each rate_limit MUST pass a distinct name: — without it actionpack derives the
  # same cache key for every call on the controller, collapsing these into one
  # shared counter. That let high-frequency RFC 8628 device polling (on the token
  # endpoint) exhaust the budget and 429 unrelated token/refresh/revoke/introspect
  # requests, including the poll that completes a just-approved login.
  #
  # The token endpoint also carries device-code polling, which is legitimately
  # frequent and can come from several devices behind one NAT, so its bucket has
  # generous headroom. Per-device poll abuse is separately bounded by the slow_down
  # interval, and none of these endpoints exposes a brute-forceable secret (tokens,
  # codes, and client secrets are opaque high-entropy values), so the limit is a
  # DoS guard rather than a credential guard.
  rate_limit to: 120, within: 1.minute, name: "oidc_token", only: [:token, :revoke, :introspect, :device_authorization], with: -> {
    render json: {error: "too_many_requests", error_description: "Rate limit exceeded. Try again later."}, status: :too_many_requests
  }
  # Browser-facing authorization flow — kept on its own counter so token-endpoint
  # traffic can never consume the interactive login budget (or vice versa).
  rate_limit to: 30, within: 1.minute, name: "oidc_authorize", only: [:authorize, :consent], with: -> {
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
      introspection_endpoint: "#{base_url}/oauth/introspect",
      userinfo_endpoint: "#{base_url}/oauth/userinfo",
      device_authorization_endpoint: "#{base_url}/oauth/device_authorization",
      jwks_uri: "#{base_url}/.well-known/jwks.json",
      end_session_endpoint: "#{base_url}/logout",
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: SUPPORTED_GRANT_TYPES,
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: OidcScopes::SUPPORTED,
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: [
        "sub",              # Always included
        "email",            # email scope
        "email_verified",   # email scope
        "name",             # profile scope
        "preferred_username", # profile scope
        "updated_at",       # profile scope
        "groups"            # groups scope
        # Note: Custom claims are also supported but not listed here
        # ID-token-only claims (auth_time, acr, azp, at_hash, nonce) are not listed
      ],
      code_challenge_methods_supported: ["S256"],
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true,
      request_parameter_supported: false,
      claims_parameter_supported: true
    }

    # Only advertise dynamic client registration when it is enabled (RFC 7591).
    if Application.dynamic_registration_enabled?
      config[:registration_endpoint] = "#{base_url}/oauth/register"
    end

    render json: config
  end

  # GET /.well-known/jwks.json
  def jwks
    render json: OidcJwtService.jwks
  end

  # POST /oauth/device_authorization
  # RFC 8628 §3.1-3.2 — Device Authorization Request/Response.
  # Public (PKCE) client presents its client_id and gets back a device_code the
  # client polls with, plus a short user_code the human types on the /device page.
  def device_authorization
    client_id, client_secret = extract_client_credentials
    application = Application.find_by(client_id: client_id, app_type: "oidc")

    unless application&.active?
      render json: {error: "invalid_client", error_description: "Unknown or inactive client"}, status: :unauthorized
      return
    end

    # RFC 8628 §3.1: the device authorization request must authenticate the client
    # per its type. Public (PKCE) clients present only their client_id; a
    # confidential client must also prove possession of its secret, otherwise an
    # attacker knowing the public client_id could initiate a request in its name.
    if application.confidential_client?
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: {error: "invalid_client", error_description: "Invalid client credentials"}, status: :unauthorized
        return
      end
    end

    # Only accept scopes we support (mirrors the authorize endpoint).
    requested_scope = (params[:scope].to_s.split & OidcScopes::SUPPORTED).join(" ")
    requested_scope = "openid" if requested_scope.blank?

    # PKCE is optional but recommended for device flow (RFC 8628 §5.5). If the
    # client sends a challenge here it must send the verifier at the token endpoint.
    code_challenge = params[:code_challenge].presence
    code_challenge_method = params[:code_challenge_method].presence

    # Public clients have no secret, so PKCE is their only proof-of-possession.
    # Require the code_challenge up front — otherwise an intercepted device_code
    # plus the well-known public client_id would be enough to redeem tokens.
    if application.requires_pkce? && code_challenge.blank?
      render json: {error: "invalid_request", error_description: "code_challenge is required for this client"}, status: :bad_request
      return
    end

    if code_challenge_method.present? && code_challenge_method != "S256"
      render json: {error: "invalid_request", error_description: "Only S256 code_challenge_method is supported"}, status: :bad_request
      return
    end

    # RFC 8707 Resource Indicator (optional): bind the eventual token to a target.
    resource = params[:resource].presence
    if resource && !valid_resource_indicator?(resource)
      render json: {error: "invalid_target", error_description: "resource must be an absolute URI without a fragment"}, status: :bad_request
      return
    end

    device_code = OidcDeviceCode.create!(
      application: application,
      scope: requested_scope,
      nonce: params[:nonce].presence,
      resource: resource,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge.present? ? (code_challenge_method || "S256") : nil
    )

    base_url = OidcJwtService.issuer_url
    verification_uri = "#{base_url}/device"

    response.headers["Cache-Control"] = "no-store"
    render json: {
      device_code: device_code.plaintext_device_code,
      user_code: device_code.user_code,
      verification_uri: verification_uri,
      verification_uri_complete: "#{verification_uri}?user_code=#{device_code.user_code}",
      expires_in: (device_code.expires_at - Time.current).to_i,
      interval: device_code.interval
    }
  end

  # GET /oauth/authorize
  def authorize
    # @application and a validated redirect_uri are guaranteed by the before_actions.
    # Read the remaining parameters (ignore forward auth tokens and other unknown params).
    client_id = params[:client_id]
    redirect_uri = params[:redirect_uri]
    state = params[:state]
    nonce = params[:nonce]
    scope = params[:scope] || "openid"
    response_type = params[:response_type]
    code_challenge = params[:code_challenge]
    code_challenge_method = params[:code_challenge_method] || "S256"
    resource = params[:resource] # RFC 8707 Resource Indicator (target audience)

    # ============================================================================
    # client_id and redirect_uri are already validated (see before_actions).
    # All subsequent errors should redirect back to the client with error parameters
    # per OAuth2 RFC 6749 Section 4.1.2.1
    # ============================================================================

    # Reject request objects (JWT-encoded authorization parameters)
    # Per OIDC Core §3.1.2.6: If request parameter is present and not supported,
    # return request_not_supported error
    if params[:request].present? || params[:request_uri].present?
      Rails.logger.error "OAuth: Request object not supported"
      redirect_authorize_error(redirect_uri, "request_not_supported", description: "Request objects are not supported", state: state)
      return
    end

    # Validate response_type (now we can safely redirect with error)
    unless response_type == "code"
      Rails.logger.error "OAuth: Invalid response_type: #{response_type}"
      redirect_authorize_error(redirect_uri, "unsupported_response_type", description: "Only 'code' response_type is supported", state: state)
      return
    end

    # RFC 8707 §2: if a resource indicator is supplied it must be a valid target,
    # otherwise the request is rejected with error=invalid_target.
    if resource.present? && !valid_resource_indicator?(resource)
      redirect_authorize_error(redirect_uri, "invalid_target", description: "resource must be an absolute URI without a fragment", state: state)
      return
    end

    # Validate PKCE parameters if present (now we can safely redirect with error)
    if code_challenge.present?
      unless code_challenge_method == "S256"
        Rails.logger.error "OAuth: Invalid code_challenge_method: #{code_challenge_method}"
        redirect_authorize_error(redirect_uri, "invalid_request", description: "Invalid code_challenge_method: only 'S256' is supported", state: state)
        return
      end

      # Validate code challenge format (base64url-encoded, 43-128 characters)
      unless code_challenge.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
        Rails.logger.error "OAuth: Invalid code_challenge format"
        redirect_authorize_error(redirect_uri, "invalid_request", description: "Invalid code_challenge format: must be 43-128 characters of base64url encoding", state: state)
        return
      end
    end

    # Normalize requested scopes to the set we support. Needed here so claims
    # validation below can check claim→scope coverage against what will actually
    # be granted.
    requested_scopes = scope.split(" ") & OidcScopes::SUPPORTED
    scope = requested_scopes.join(" ")

    # Parse claims parameter (JSON string) for OIDC claims request
    # Per OIDC Core §5.5: The claims parameter is a JSON object that requests
    # specific claims to be returned in the id_token and/or userinfo
    claims_parameter = params[:claims]
    parsed_claims = parse_claims_parameter(claims_parameter) if claims_parameter.present?

    # Validate claims parameter format if present
    if claims_parameter.present? && parsed_claims.nil?
      Rails.logger.error "OAuth: Invalid claims parameter format"
      redirect_authorize_error(redirect_uri, "invalid_request", description: "Invalid claims parameter: must be valid JSON", state: state)
      return
    end

    # Validate that requested claims are covered by granted scopes
    if parsed_claims.present?
      validation_result = validate_claims_against_scopes(parsed_claims, requested_scopes)
      unless validation_result[:valid]
        Rails.logger.error "OAuth: Claims parameter requests claims not covered by scopes: #{validation_result[:errors]}"
        redirect_authorize_error(redirect_uri, "invalid_scope", description: "Claims parameter requests claims not covered by granted scopes", state: state)
        return
      end
    end

    # Check if application is active (now we can safely redirect with error)
    unless @application.active?
      Rails.logger.error "OAuth: Application is not active: #{@application.name}"
      redirect_authorize_error(redirect_uri, "unauthorized_client", description: "Application is not active", state: state)
      return
    end

    # Check if user is authenticated
    unless authenticated?
      # Handle prompt=none - no UI allowed, return error immediately
      # Per OIDC Core spec §3.1.2.6: If prompt=none and user not authenticated,
      # return login_required error without showing any UI
      if params[:prompt] == "none"
        redirect_authorize_error(redirect_uri, "login_required", state: state)
        return
      end

      # Normal flow: store OAuth parameters and redirect to sign in
      session[:oauth_params] = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        state: state,
        nonce: nonce,
        scope: scope,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
        resource: resource,
        claims_requests: parsed_claims&.to_json
      }
      # Store the current URL (with all OAuth params) for redirect after authentication
      session[:return_to_after_authenticating] = request.url
      redirect_to signin_path, alert: "Please sign in to continue"
      return
    end

    # Handle prompt=login - force re-authentication
    # Per OIDC Core spec §3.1.2.1: If prompt=login, the Authorization Server MUST prompt
    # the End-User for reauthentication, even if the End-User is currently authenticated
    if params[:prompt] == "login"
      # Destroy current session to force re-authentication
      # This creates a fresh authentication event with a new auth_time
      Current.session&.destroy!

      # Clear the session cookie so the user is truly logged out
      cookies.delete(:session_id)

      # Store the current URL (which contains all OAuth params) for redirect after login
      # Remove prompt=login to prevent infinite re-auth loop
      return_url = remove_query_param(request.url, "prompt")
      session[:return_to_after_authenticating] = return_url

      redirect_to signin_path, alert: "Please sign in to continue"
      return
    end

    # Handle max_age - require re-authentication if session is too old
    # Per OIDC Core spec §3.1.2.1: If max_age is provided and the auth time is older,
    # the Authorization Server MUST prompt for reauthentication
    if params[:max_age].present?
      max_age_seconds = params[:max_age].to_i
      # Calculate session age
      session_age_seconds = Time.current.to_i - Current.session.created_at.to_i

      if session_age_seconds >= max_age_seconds
        # Session is too old - require re-authentication
        # Store the return URL in Rails session, then destroy the Session record

        # Store return URL before destroying anything
        # Remove max_age from return URL to prevent infinite re-auth loop
        return_url = remove_query_param(request.url, "max_age")
        session[:return_to_after_authenticating] = return_url

        # Destroy the Session record and clear its cookie
        Current.session&.destroy!
        cookies.delete(:session_id)
        Current.session = nil

        redirect_to signin_path, alert: "Please sign in to continue"
        return
      end
    end

    # Get the authenticated user
    user = Current.session.user

    # Check if user is allowed to access this application
    unless @application.user_allowed?(user)
      render plain: "You do not have permission to access this application", status: :forbidden
      return
    end

    unless requested_scopes.include?("openid")
      redirect_authorize_error(redirect_uri, "invalid_scope", description: "The 'openid' scope is required", state: state)
      return
    end

    # Check if application is configured to skip consent
    # If so, automatically create consent and proceed without showing consent screen
    if @application.skip_consent?
      # Create or update consent record automatically for trusted applications
      consent = OidcUserConsent.find_or_initialize_by(user: user, application: @application)
      consent.scopes_granted = requested_scopes.join(" ")
      consent.claims_requests = parsed_claims || {}
      consent.granted_at = Time.current
      consent.save!

      # Generate authorization code directly
      auth_code = OidcAuthorizationCode.create!(
        application: @application,
        user: user,
        redirect_uri: redirect_uri,
        scope: scope,
        nonce: nonce,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
        resource: resource,
        claims_requests: parsed_claims || {},
        auth_time: Current.session.created_at.to_i,
        acr: Current.session.acr,
        expires_at: 10.minutes.from_now
      )

      # Redirect back to client with authorization code (plaintext)
      redirect_uri = "#{redirect_uri}?code=#{auth_code.plaintext_code}"
      redirect_uri += "&state=#{CGI.escape(state)}" if state.present?
      redirect_to redirect_uri, allow_other_host: true
      return
    end

    # Check if user has already granted consent for these scopes
    existing_consent = user.has_oidc_consent?(@application, requested_scopes)
    if existing_consent && claims_match_consent?(parsed_claims, existing_consent)
      # User has already consented, generate authorization code directly
      auth_code = OidcAuthorizationCode.create!(
        application: @application,
        user: user,
        redirect_uri: redirect_uri,
        scope: scope,
        nonce: nonce,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
        resource: resource,
        claims_requests: parsed_claims || {},
        auth_time: Current.session.created_at.to_i,
        acr: Current.session.acr,
        expires_at: 10.minutes.from_now
      )

      # Redirect back to client with authorization code (plaintext)
      redirect_uri = "#{redirect_uri}?code=#{auth_code.plaintext_code}"
      redirect_uri += "&state=#{CGI.escape(state)}" if state.present?
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
      code_challenge_method: code_challenge_method,
      resource: resource,
      claims_requests: parsed_claims&.to_json
    }

    # Render consent page with dynamic CSP for OAuth redirect
    @redirect_uri = redirect_uri
    @scopes = requested_scopes

    # Add the redirect URI to CSP form-action for this specific request.
    # This allows the OAuth redirect to work while maintaining security:
    # CSP must allow the OAuth client's redirect_uri as a form submission target.
    allow_form_action_for_redirect_uri(redirect_uri)

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
      redirect_authorize_error(oauth_params["redirect_uri"], "access_denied", state: oauth_params["state"])
      return
    end

    # Find the application
    client_id = oauth_params["client_id"]
    application = Application.find_by(client_id: client_id, app_type: "oidc")

    # Check if application is active (redirect with OAuth error)
    unless application&.active?
      Rails.logger.error "OAuth: Application is not active: #{application&.name || client_id}"
      session.delete(:oauth_params)
      redirect_authorize_error(oauth_params["redirect_uri"], "unauthorized_client", description: "Application is not active", state: oauth_params["state"])
      return
    end

    user = Current.session.user

    requested_scopes = oauth_params["scope"].split(" ") & OidcScopes::SUPPORTED
    parsed_claims = begin
      JSON.parse(oauth_params["claims_requests"])
    rescue
      {}
    end

    consent = OidcUserConsent.find_or_initialize_by(user: user, application: application)
    consent.scopes_granted = requested_scopes.join(" ")
    consent.claims_requests = parsed_claims
    consent.granted_at = Time.current
    consent.save!

    # Generate authorization code
    auth_code = OidcAuthorizationCode.create!(
      application: application,
      user: user,
      redirect_uri: oauth_params["redirect_uri"],
      scope: oauth_params["scope"],
      nonce: oauth_params["nonce"],
      code_challenge: oauth_params["code_challenge"],
      code_challenge_method: oauth_params["code_challenge_method"],
      resource: oauth_params["resource"],
      claims_requests: parsed_claims,
      auth_time: Current.session.created_at.to_i,
      acr: Current.session.acr,
      expires_at: 10.minutes.from_now
    )

    # Clear OAuth params from session
    session.delete(:oauth_params)

    # Redirect back to client with authorization code (plaintext)
    redirect_uri = "#{oauth_params["redirect_uri"]}?code=#{auth_code.plaintext_code}"
    redirect_uri += "&state=#{CGI.escape(oauth_params["state"])}" if oauth_params["state"]

    redirect_to redirect_uri, allow_other_host: true
  end

  # POST /oauth/token
  def token
    # Reject claims parameter - per OIDC security, claims parameter is only valid
    # in authorization requests, not at the token endpoint
    if params[:claims].present?
      render json: {
        error: "invalid_request",
        error_description: "claims parameter is not allowed at the token endpoint"
      }, status: :bad_request
      return
    end

    grant_type = params[:grant_type]

    case grant_type
    when "authorization_code"
      handle_authorization_code_grant
    when "refresh_token"
      handle_refresh_token_grant
    when "urn:ietf:params:oauth:grant-type:device_code"
      handle_device_code_grant
    else
      render json: {error: "unsupported_grant_type"}, status: :bad_request
    end
  end

  # RFC 8628 §3.4-3.5 — the CLI/agent polls here with its device_code until the
  # user approves on the /device page, then receives the standard token triple.
  def handle_device_code_grant
    client_id, client_secret = extract_client_credentials

    unless client_id
      render json: {error: "invalid_client", error_description: "client_id is required"}, status: :unauthorized
      return
    end

    application = Application.find_by(client_id: client_id)
    unless application
      render json: {error: "invalid_client", error_description: "Unknown client"}, status: :unauthorized
      return
    end

    # Public clients authenticate with the device_code (+ optional PKCE); a
    # confidential client using device flow must still present its secret.
    if application.confidential_client?
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: {error: "invalid_client", error_description: "Invalid client credentials"}, status: :unauthorized
        return
      end
    end

    unless application.active?
      render json: {error: "invalid_client", error_description: "Application is not active"}, status: :forbidden
      return
    end

    device_code = OidcDeviceCode.find_by_plaintext_device_code(params[:device_code])
    unless device_code && device_code.application_id == application.id
      render json: {error: "invalid_grant", error_description: "Invalid device_code"}, status: :bad_request
      return
    end

    OidcDeviceCode.transaction do
      # Lock so concurrent polls / a poll racing with approval can't double-issue.
      device_code.lock!

      # Replay: an already-redeemed code must never mint tokens again. Mirror the
      # authorization-code reuse semantics (RFC 6749 §4.1.2) — revoke every token
      # descended from it and report the reuse distinguishably, rather than the
      # generic "Invalid device_code" returned for an unknown code.
      if device_code.redeemed?
        Rails.logger.warn "OIDC Security: Device code reuse detected for code #{device_code.id}"
        now = Time.current
        device_code.oidc_access_tokens.where(revoked_at: nil).update_all(revoked_at: now)
        device_code.oidc_refresh_tokens.where(revoked_at: nil).update_all(revoked_at: now)
        render json: {error: "invalid_grant", error_description: "Device code has already been used"}, status: :bad_request
        return
      end

      if device_code.expired?
        render json: {error: "expired_token", error_description: "The device_code has expired"}, status: :bad_request
        return
      end

      if device_code.denied?
        render json: {error: "access_denied", error_description: "The authorization request was denied"}, status: :bad_request
        return
      end

      if device_code.pending?
        # Enforce the polling interval; too-frequent polls get slow_down, and the
        # client is expected to add 5s to its interval (RFC 8628 §3.5). The bump is
        # capped at MAX_INTERVAL so a persistently fast poller can't grow it without
        # bound and starve a legitimate client before the code expires.
        if device_code.last_polled_at && (Time.current - device_code.last_polled_at) < device_code.interval
          bumped_interval = [device_code.interval + OidcDeviceCode::INTERVAL_INCREMENT, OidcDeviceCode::MAX_INTERVAL].min
          device_code.update!(interval: bumped_interval, last_polled_at: Time.current)
          render json: {error: "slow_down"}, status: :bad_request
        else
          device_code.update!(last_polled_at: Time.current)
          render json: {error: "authorization_pending"}, status: :bad_request
        end
        return
      end

      # Approved: mint tokens via the same path as the authorization code grant.
      user = device_code.user

      # Re-check authorization at mint time. Approval may have happened minutes ago;
      # an admin could have deactivated the user or removed them from the allowed
      # group in the meantime. user_allowed? covers app active, user active, and
      # group membership, so a now-unauthorized user is refused their tokens.
      unless user && application.user_allowed?(user)
        render json: {error: "access_denied", error_description: "User is no longer permitted to access this application"}, status: :bad_request
        return
      end

      consent = OidcUserConsent.find_by(user: user, application: application)
      unless consent
        Rails.logger.error "OIDC Security: Device token requested without consent record (user: #{user&.id}, app: #{application.id})"
        render json: {error: "invalid_grant", error_description: "Authorization consent not found"}, status: :bad_request
        return
      end

      # PKCE is enforced whenever the device authorization request supplied a
      # code_challenge. Clients that require PKCE (all public clients) are also
      # guaranteed to have one by the device_authorization endpoint; re-check here
      # so a device_code minted without a challenge can never redeem tokens.
      if application.requires_pkce? && !device_code.uses_pkce?
        render json: {error: "invalid_grant", error_description: "PKCE is required for this client"}, status: :bad_request
        return
      end

      if device_code.uses_pkce?
        pkce_result = validate_pkce(application, device_code, params[:code_verifier])
        unless pkce_result[:valid]
          render json: {error: pkce_result[:error], error_description: pkce_result[:error_description]}, status: pkce_result[:status]
          return
        end
      end

      # Single-use: mark the code redeemed (don't destroy it) so a replay is
      # detected as reuse — see the redeemed? check at the top of this block. The
      # cleanup job reaps redeemed codes after they expire.
      device_code.update!(redeemed_at: Time.current)

      # Device flow never carries an OIDC claims request, so there are no claims
      # to filter into the id_token.
      mint_and_render_tokens(
        application: application,
        user: user,
        grant: device_code,
        grant_association: {oidc_device_code: device_code},
        consent: consent,
        claims_requests: {}
      )
    end
  end

  def handle_authorization_code_grant
    # Get client credentials from Authorization header or params
    client_id, client_secret = extract_client_credentials

    unless client_id
      render json: {error: "invalid_client", error_description: "client_id is required"}, status: :unauthorized
      return
    end

    # Find the application
    application = Application.find_by(client_id: client_id)
    unless application
      render json: {error: "invalid_client", error_description: "Unknown client"}, status: :unauthorized
      return
    end

    # Validate client credentials based on client type
    if application.public_client?
      # Public clients don't have a secret - they MUST use PKCE (checked later)
      Rails.logger.info "OAuth: Public client authentication for #{application.name}"
    else
      # Confidential clients MUST provide valid client_secret
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: {error: "invalid_client", error_description: "Invalid client credentials"}, status: :unauthorized
        return
      end
    end

    # Check if application is active
    unless application.active?
      Rails.logger.error "OAuth: Token request for inactive application: #{application.name}"
      render json: {error: "invalid_client", error_description: "Application is not active"}, status: :forbidden
      return
    end

    # Get the authorization code
    code = params[:code]
    redirect_uri = params[:redirect_uri]
    code_verifier = params[:code_verifier]

    # Find authorization code using HMAC verification
    auth_code = OidcAuthorizationCode.find_by_plaintext(code)

    unless auth_code && auth_code.application == application
      render json: {error: "invalid_grant"}, status: :bad_request
      return
    end

    # Use a transaction with pessimistic locking to prevent code reuse
    begin
      OidcAuthorizationCode.transaction do
        # Lock the record to prevent concurrent access
        auth_code.lock!

        # Check if code has already been used (CRITICAL: check AFTER locking)
        if auth_code.used?
          # Per OAuth 2.0 spec, if an auth code is reused, revoke every token
          # descended from it (both generations across any rotations).
          Rails.logger.warn "OAuth Security: Authorization code reuse detected for code #{auth_code.id}"
          now = Time.current
          auth_code.oidc_access_tokens.where(revoked_at: nil).update_all(revoked_at: now)
          auth_code.oidc_refresh_tokens.where(revoked_at: nil).update_all(revoked_at: now)

          render json: {
            error: "invalid_grant",
            error_description: "Authorization code has already been used"
          }, status: :bad_request
          return
        end

        # Check if code is expired
        if auth_code.expires_at < Time.current
          render json: {error: "invalid_grant", error_description: "Authorization code expired"}, status: :bad_request
          return
        end

        # Validate redirect URI matches
        unless auth_code.redirect_uri == redirect_uri
          render json: {error: "invalid_grant", error_description: "Redirect URI mismatch"}, status: :bad_request
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

        # Re-check authorization at mint time: the user may have been deactivated or
        # removed from the allowed group between /authorize and this token request.
        unless user && application.user_allowed?(user)
          render json: {error: "access_denied", error_description: "User is no longer permitted to access this application"}, status: :bad_request
          return
        end

        # Find user consent for this application before minting, so a missing
        # consent record can't leave orphaned tokens committed in this transaction.
        consent = OidcUserConsent.find_by(user: user, application: application)

        unless consent
          Rails.logger.error "OIDC Security: Token requested without consent record (user: #{user.id}, app: #{application.id})"
          render json: {error: "invalid_grant", error_description: "Authorization consent not found"}, status: :bad_request
          return
        end

        # auth_time, acr, and nonce come from the authorization code (captured at
        # /authorize time); the claims request filters which id_token claims appear.
        mint_and_render_tokens(
          application: application,
          user: user,
          grant: auth_code,
          grant_association: {oidc_authorization_code: auth_code},
          consent: consent,
          claims_requests: auth_code.parsed_claims_requests
        )
      end
    rescue ActiveRecord::RecordNotFound
      render json: {error: "invalid_grant"}, status: :bad_request
    end
  end

  def handle_refresh_token_grant
    # Get client credentials from Authorization header or params
    client_id, client_secret = extract_client_credentials

    unless client_id
      render json: {error: "invalid_client", error_description: "client_id is required"}, status: :unauthorized
      return
    end

    # Find the application
    application = Application.find_by(client_id: client_id)
    unless application
      render json: {error: "invalid_client", error_description: "Unknown client"}, status: :unauthorized
      return
    end

    # Validate client credentials based on client type
    if application.public_client?
      # Public clients don't have a secret
      Rails.logger.info "OAuth: Public client refresh token request for #{application.name}"
    else
      # Confidential clients MUST provide valid client_secret
      unless client_secret.present? && application.authenticate_client_secret(client_secret)
        render json: {error: "invalid_client", error_description: "Invalid client credentials"}, status: :unauthorized
        return
      end
    end

    # Check if application is active
    unless application.active?
      Rails.logger.error "OAuth: Refresh token request for inactive application: #{application.name}"
      render json: {error: "invalid_client", error_description: "Application is not active"}, status: :forbidden
      return
    end

    # Get the refresh token
    refresh_token = params[:refresh_token]
    unless refresh_token.present?
      render json: {error: "invalid_request", error_description: "refresh_token is required"}, status: :bad_request
      return
    end

    # Find the refresh token record using indexed token prefix lookup
    refresh_token_record = OidcRefreshToken.find_by_token(refresh_token)

    # Verify the token belongs to the correct application
    unless refresh_token_record && refresh_token_record.application == application
      render json: {error: "invalid_grant", error_description: "Invalid refresh token"}, status: :bad_request
      return
    end

    # Check if refresh token is expired
    if refresh_token_record.expired?
      render json: {error: "invalid_grant", error_description: "Refresh token expired"}, status: :bad_request
      return
    end

    # Check if refresh token is revoked
    if refresh_token_record.revoked?
      # If a revoked refresh token is used, it's a security issue
      # Revoke all tokens in the family (token rotation attack detection)
      Rails.logger.warn "OAuth Security: Revoked refresh token reuse detected for token family #{refresh_token_record.token_family_id}"
      refresh_token_record.revoke_family!

      render json: {error: "invalid_grant", error_description: "Refresh token has been revoked"}, status: :bad_request
      return
    end

    # Get the user
    user = refresh_token_record.user

    # Re-check authorization at mint time. Refresh tokens are long-lived (up to
    # 30 days), so re-evaluate every refresh: a user deactivated or removed from
    # the allowed group must not be able to keep minting access tokens. Checked
    # before rotation so a denied refresh has no side effects.
    unless user && application.user_allowed?(user)
      render json: {error: "access_denied", error_description: "User is no longer permitted to access this application"}, status: :bad_request
      return
    end

    # Find user consent for this application. Checked *before* rotation: a refresh
    # refused for want of consent must have no side effects, or it leaves the
    # presented token revoked and a freshly minted, unreachable token pair behind.
    consent = OidcUserConsent.find_by(user: user, application: application)

    unless consent
      Rails.logger.error "OIDC Security: Refresh token used without consent record (user: #{user.id}, app: #{application.id})"
      render json: {error: "invalid_grant", error_description: "Authorization consent not found"}, status: :bad_request
      return
    end

    # Carry the issuing-code FK forward across rotations so replay revocation
    # reaches every descendant token in the chain — for both the authorization-code
    # and device-code grants (a token descends from exactly one of them).
    issuing_auth_code = refresh_token_record.oidc_authorization_code
    issuing_device_code = refresh_token_record.oidc_device_code

    new_access_token = nil
    new_refresh_token = nil
    lost_rotation_race = false

    # Rotate under a row lock, as the authorization-code and device-code grants
    # already do. Without it two concurrent requests presenting the same refresh
    # token both pass the `revoked?` check above and both mint a token pair,
    # which silently defeats rotation reuse detection.
    OidcRefreshToken.transaction do
      refresh_token_record.lock!

      if refresh_token_record.revoked?
        # A concurrent request rotated this token between our check and the lock.
        lost_rotation_race = true
      else
        refresh_token_record.revoke!

        new_access_token = OidcAccessToken.create!(
          application: application,
          user: user,
          scope: refresh_token_record.scope,
          oidc_authorization_code: issuing_auth_code,
          oidc_device_code: issuing_device_code,
          resource: refresh_token_record.resource
        )

        new_refresh_token = OidcRefreshToken.create!(
          application: application,
          user: user,
          oidc_access_token: new_access_token,
          oidc_authorization_code: issuing_auth_code,
          oidc_device_code: issuing_device_code,
          scope: refresh_token_record.scope,
          token_family_id: refresh_token_record.token_family_id,  # Keep same family for rotation tracking
          auth_time: refresh_token_record.auth_time,  # Carry over original auth_time
          acr: refresh_token_record.acr,  # Carry over original acr
          resource: refresh_token_record.resource  # Carry the bound audience across rotation
        )
      end
    end

    if lost_rotation_race
      # Two presentations of one token is the signature of a leaked refresh token,
      # so treat it exactly as the pre-lock reuse check does: burn the family.
      Rails.logger.warn "OAuth Security: Concurrent refresh token reuse detected for token family #{refresh_token_record.token_family_id}"
      refresh_token_record.revoke_family!
      render json: {error: "invalid_grant", error_description: "Refresh token has been revoked"}, status: :bad_request
      return
    end

    # Generate new ID token (JWT with pairwise SID, at_hash, auth_time, acr; no nonce for refresh grants)
    # auth_time and acr come from the original refresh token (carried over from initial auth)
    # scopes determine which claims are included (per OIDC Core spec)
    # claims_requests parameter filters which claims are included (from original consent)
    # As in mint_and_render_tokens: hash what the client is actually given.
    access_token_value = new_access_token.wire_value(consent: consent)

    id_token = OidcJwtService.generate_id_token(
      user,
      application,
      consent: consent,
      access_token: access_token_value,
      auth_time: refresh_token_record.auth_time,
      acr: refresh_token_record.acr,
      scopes: refresh_token_record.scope,
      claims_requests: consent.parsed_claims_requests
    )

    # RFC6749-5.1: Token endpoint MUST return Cache-Control: no-store
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    # Return new tokens
    render json: {
      access_token: access_token_value,  # Opaque handle, or an RFC 9068 JWT (ADR 0007)
      token_type: "Bearer",
      expires_in: application.access_token_ttl || 3600,
      id_token: id_token,  # JWT
      refresh_token: new_refresh_token.token,  # Opaque token
      scope: refresh_token_record.scope
    }
  rescue ActiveRecord::RecordNotFound
    render json: {error: "invalid_grant"}, status: :bad_request
  end

  # GET/POST /oauth/userinfo
  # OIDC Core spec: UserInfo endpoint MUST support GET, SHOULD support POST
  def userinfo
    # Extract access token from the Authorization header or a form-encoded body.
    # RFC 6750 §2.3 discourages the URI query parameter form: it puts bearer
    # tokens into proxy logs, browser history and Referer headers, so it is not
    # accepted here even though the RFC describes it.
    token = if request.headers["Authorization"]&.start_with?("Bearer ")
      request.headers["Authorization"].sub("Bearer ", "")
    elsif request.request_parameters["access_token"].present?
      request.request_parameters["access_token"]
    end

    unless token
      head :unauthorized
      return
    end

    # Find and validate access token (opaque token with BCrypt hashing)
    access_token = OidcAccessToken.find_by_presented_token(token)
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
    # The token's user must still be active: disabling an account has to cut off
    # its tokens immediately, not at token expiry (up to 24h away).
    user = access_token.user
    unless user&.active?
      head :unauthorized
      return
    end

    # Find user consent for this application to get pairwise SID
    consent = OidcUserConsent.find_by(user: user, application: access_token.application)
    subject = consent&.sid || user.id.to_s

    # Parse scopes from access token (space-separated string)
    requested_scopes = access_token.scope.to_s.split

    # Get claims_requests from consent (if available) for UserInfo context
    userinfo_claims = consent&.parsed_claims_requests&.dig("userinfo") || {}

    # Return user claims (filter by scope per OIDC Core spec)
    # Required claims (always included - cannot be filtered by claims parameter)
    claims = {
      sub: subject
    }

    # Email claims (only if 'email' scope requested AND requested in claims parameter)
    if requested_scopes.include?("email")
      if should_include_claim_for_userinfo?("email", userinfo_claims)
        claims[:email] = user.email_address
      end
      if should_include_claim_for_userinfo?("email_verified", userinfo_claims)
        claims[:email_verified] = true
      end
    end

    # Profile claims (only if 'profile' scope requested)
    # Per OIDC Core spec section 5.4, include available profile claims
    # Only include claims we have data for - omit unknown claims rather than returning null
    if requested_scopes.include?("profile")
      if should_include_claim_for_userinfo?("preferred_username", userinfo_claims)
        claims[:preferred_username] = user.username.presence || user.email_address
      end
      if should_include_claim_for_userinfo?("name", userinfo_claims)
        claims[:name] = user.name.presence || user.email_address
      end
      if should_include_claim_for_userinfo?("updated_at", userinfo_claims)
        claims[:updated_at] = user.updated_at.to_i
      end
    end

    # Groups claim (only if 'groups' scope requested AND requested in claims parameter)
    if requested_scopes.include?("groups") && user.groups.any?
      if should_include_claim_for_userinfo?("groups", userinfo_claims)
        claims[:groups] = user.groups.pluck(:name)
      end
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

    # Filter custom claims based on claims parameter
    # If claims parameter is present, only include requested custom claims
    if userinfo_claims.any?
      claims = filter_custom_claims_for_userinfo(claims, userinfo_claims)
    end

    # Security: Don't cache user data responses
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    render json: claims
  end

  # POST /oauth/introspect
  # RFC 7662 - OAuth 2.0 Token Introspection.
  # A resource server (e.g. c2a2) presents an opaque access token and its own
  # client credentials; we reply whether the token is active and, as an extension,
  # the user's groups so the resource server can authorize on group membership.
  def introspect
    # RFC 7662 §2.1: the caller (resource server) MUST authenticate. Only a
    # registered confidential client may introspect.
    caller_id, caller_secret = extract_client_credentials
    caller = Application.find_by(client_id: caller_id) if caller_id.present?

    unless caller&.confidential_client? && caller.active? &&
        caller_secret.present? && caller.authenticate_client_secret(caller_secret)
      render json: {error: "invalid_client", error_description: "Caller authentication failed"}, status: :unauthorized
      return
    end

    token_value = params[:token]
    if token_value.blank?
      render json: {error: "invalid_request", error_description: "token parameter is required"}, status: :bad_request
      return
    end

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    access_token = OidcAccessToken.find_by_presented_token(token_value)

    # Inactive/unknown/expired/revoked tokens (or those for a disabled app) are
    # reported as simply inactive per RFC 7662 §2.2 — never an error.
    unless access_token&.active? && access_token.application&.active? && access_token.user&.active?
      render json: {active: false}
      return
    end

    # RFC 7662 §4: a token must only be disclosed to a resource server authorized
    # to introspect it. Otherwise any confidential client could harvest every
    # user's identity by introspecting tokens issued to other clients. A caller is
    # authorized only for tokens issued to itself, or tokens whose bound audience
    # (RFC 8707 resource) it is registered to serve. Unauthorized callers get the
    # same inactive response as an unknown token, disclosing nothing.
    unless caller_may_introspect?(caller, access_token)
      Rails.logger.warn "OAuth: Client #{caller.client_id} not authorized to introspect token for resource #{access_token.resource.inspect}"
      render json: {active: false}
      return
    end

    user = access_token.user
    application = access_token.application
    consent = OidcUserConsent.find_by(user: user, application: application)
    scopes = access_token.scope.to_s.split

    body = {
      active: true,
      scope: access_token.scope,
      client_id: application.client_id,
      token_type: "Bearer",
      exp: access_token.expires_at.to_i,
      iat: access_token.created_at.to_i,
      sub: consent&.sid || user.id.to_s,
      # RFC 8707: the resource the token was bound to (falls back to the client
      # when no resource indicator was used at authorization time).
      aud: access_token.resource.presence || application.client_id
    }

    # Disclose identity claims only when the token actually carries the scope that
    # grants them (mirrors the userinfo endpoint) — a token without `email`/`groups`
    # scope must not leak the user's email or group memberships.
    body[:username] = user.email_address if scopes.include?("email")
    body[:groups] = user.groups.pluck(:name) if scopes.include?("groups")

    render json: body
  end

  # A caller may introspect a token issued to itself, or a token bound (RFC 8707)
  # to a resource the caller is registered to serve.
  def caller_may_introspect?(caller, access_token)
    return true if access_token.application_id == caller.id

    resource = access_token.resource.presence
    resource.present? && caller.serves_resource?(resource)
  end

  # POST /oauth/revoke
  # RFC 7009 - Token Revocation
  def revoke
    # Get client credentials
    client_id, client_secret = extract_client_credentials

    unless client_id
      # RFC 7009 says we should return 200 OK even for invalid client
      # But log the attempt for security monitoring
      Rails.logger.warn "OAuth: Token revocation attempted with invalid client credentials"
      head :ok
      return
    end

    # Find and validate the application
    application = Application.find_by(client_id: client_id)
    unless application
      Rails.logger.warn "OAuth: Token revocation attempted for invalid application: #{client_id}"
      head :ok
      return
    end

    # RFC 7009 §2.1: a public client authenticates with client_id alone — requiring
    # a secret locked public clients out of revoking their own tokens entirely.
    # Confidential clients must still present their secret.
    if application.confidential_client? && !application.authenticate_client_secret(client_secret)
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
      render json: {error: "invalid_request", error_description: "token parameter is required"}, status: :bad_request
      return
    end

    # Try to find and revoke the token
    # Check token type hint first for efficiency, otherwise try both
    revoked = false

    # RFC 7009 §2.1: "the authorization server ... validates whether the token was
    # issued to the client making the revocation request". Without this any
    # registered client could revoke any other client's tokens — a denial of
    # service against every relying party behind this IdP.
    owned_by_caller = ->(record) { record.application_id == application.id }

    if token_type_hint == "refresh_token" || token_type_hint.nil?
      # Try to find as refresh token
      refresh_token_record = OidcRefreshToken.find_by_token(token)

      if refresh_token_record && owned_by_caller.call(refresh_token_record)
        refresh_token_record.revoke!
        Rails.logger.info "OAuth: Refresh token revoked for application #{application.name}"
        revoked = true
      elsif refresh_token_record
        Rails.logger.warn "OAuth: Client #{application.client_id} attempted to revoke a refresh token issued to another client"
      end
    end

    if !revoked && (token_type_hint == "access_token" || token_type_hint.nil?)
      # Try to find as access token
      access_token_record = OidcAccessToken.find_by_presented_token(token)

      if access_token_record && owned_by_caller.call(access_token_record)
        access_token_record.revoke!
        Rails.logger.info "OAuth: Access token revoked for application #{application.name}"
      elsif access_token_record
        Rails.logger.warn "OAuth: Client #{application.client_id} attempted to revoke an access token issued to another client"
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

    params[:id_token_hint]
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
        redirect_uri += "?state=#{CGI.escape(state)}" if state.present?
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

  # Redirect back to the client's redirect_uri with an OAuth 2.0 authorization
  # error (RFC 6749 §4.1.2.1). Extracted because the authorize / consent flows
  # report errors this same way ~a dozen times. Composes the query safely so a
  # redirect_uri that already carries a query string gets "&error=..." rather than
  # a second "?", and CGI-escapes the description and state.
  # Mints the access + refresh + id-token triple and renders the RFC 6749 §5.1
  # token response. Shared by the authorization-code and device-code grants: both
  # redeem a `grant` (the auth code / device code) exposing scope/resource/nonce/
  # auth_time/acr, and both tie the tokens back to it via `grant_association` (the
  # belongs_to used for replay revocation). The caller marks the grant consumed
  # before calling this, and both callers run inside the grant's locked transaction.
  def mint_and_render_tokens(application:, user:, grant:, grant_association:, consent:, claims_requests:)
    access_token_record = OidcAccessToken.create!(
      application: application,
      user: user,
      scope: grant.scope,
      resource: grant.resource,
      **grant_association
    )

    refresh_token_record = OidcRefreshToken.create!(
      application: application,
      user: user,
      oidc_access_token: access_token_record,
      scope: grant.scope,
      auth_time: grant.auth_time,
      acr: grant.acr,
      resource: grant.resource,
      **grant_association
    )

    # The value the client actually receives — opaque handle or RFC 9068 JWT
    # (ADR 0007). Computed once: at_hash must cover the token *as delivered*
    # (OIDC Core §3.1.3.6), so hashing the internal handle would break any
    # client that validates it.
    access_token_value = access_token_record.wire_value(consent: consent)

    id_token = OidcJwtService.generate_id_token(
      user,
      application,
      consent: consent,
      nonce: grant.nonce,
      access_token: access_token_value,
      auth_time: grant.auth_time,
      acr: grant.acr,
      scopes: grant.scope,
      claims_requests: claims_requests
    )

    # RFC 6749 §5.1: the token response MUST NOT be cached.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    render json: {
      access_token: access_token_value,
      token_type: "Bearer",
      expires_in: application.access_token_ttl || 3600,
      id_token: id_token,
      refresh_token: refresh_token_record.token,
      scope: grant.scope
    }
  end

  def redirect_authorize_error(redirect_uri, error, description: nil, state: nil)
    query = {error: error}
    query[:error_description] = description if description
    query[:state] = state if state.present?
    separator = redirect_uri.include?("?") ? "&" : "?"
    redirect_to "#{redirect_uri}#{separator}#{query.to_query}", allow_other_host: true
  end

  # Look up @application from client_id. RFC 6749 §4.1.2.1 requires that an
  # invalid client_id be reported on-page, not via redirect.
  def set_application
    client_id = params[:client_id]

    unless client_id.present?
      render plain: "Invalid request: client_id is required", status: :bad_request
      return
    end

    @application = Application.find_by(client_id: client_id, app_type: "oidc")
    return if @application

    Rails.logger.error "OAuth: Invalid request - application not found for client_id: #{client_id}"

    error_msg = if Rails.env.development?
      all_oidc_apps = Application.where(app_type: "oidc")
      Rails.logger.error "OAuth: Available OIDC applications: #{all_oidc_apps.pluck(:id, :client_id, :name)}"
      "Invalid request: Application not found for client_id '#{client_id}'. Available OIDC applications: #{all_oidc_apps.pluck(:name, :client_id).map { |name, id| "#{name} (#{id})" }.join(", ")}"
    else
      "Invalid request: Application not found"
    end

    render plain: error_msg, status: :bad_request
  end

  # Confirm the redirect_uri param is present and registered on @application.
  # Must run after set_application. Errors render on-page per RFC 6749 §4.1.2.1.
  def validate_redirect_uri
    redirect_uri = params[:redirect_uri]

    unless redirect_uri.present?
      render plain: "Invalid request: redirect_uri is required", status: :bad_request
      return
    end

    return if @application.parsed_redirect_uris.include?(redirect_uri)

    Rails.logger.error "OAuth: Invalid request - redirect URI mismatch. Expected: #{@application.parsed_redirect_uris}, Got: #{redirect_uri}"

    error_msg = if Rails.env.development?
      "Invalid request: Redirect URI mismatch. Application is configured for: #{@application.parsed_redirect_uris.join(", ")}, but received: #{redirect_uri}"
    else
      "Invalid request: Redirect URI not registered for this application"
    end

    render plain: error_msg, status: :bad_request
  end

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
    return {valid: true} unless pkce_provided

    # PKCE was provided during authorization but no verifier sent with token request
    unless code_verifier.present?
      return {
        valid: false,
        error: "invalid_request",
        error_description: "code_verifier is required when code_challenge was provided",
        status: :bad_request
      }
    end

    # Validate code verifier format (per RFC 7636: [A-Za-z0-9\-._~], 43-128 characters)
    unless code_verifier.match?(/\A[A-Za-z0-9.\-_~]{43,128}\z/)
      return {
        valid: false,
        error: "invalid_request",
        error_description: "Invalid code_verifier format. Must be 43-128 characters [A-Z/a-z/0-9/-/./_/~]",
        status: :bad_request
      }
    end

    # Recreate code challenge based on method
    expected_challenge = case auth_code.code_challenge_method
    when "S256"
      Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
    else
      return {
        valid: false,
        error: "invalid_request",
        error_description: "Unsupported code challenge method: only 'S256' is supported",
        status: :bad_request
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

    {valid: true}
  end

  # RFC 8707 §2: a resource indicator must be an absolute URI and MUST NOT
  # include a fragment component. We validate syntax only (pass-through) — the
  # resource server enforces the audience when it introspects the token.
  def valid_resource_indicator?(value)
    return false if value.blank?
    uri = URI.parse(value)
    uri.absolute? && uri.fragment.nil?
  rescue URI::InvalidURIError
    false
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
      return nil if Rails.env.production? && parsed_uri.scheme != "https"

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

  # Parse claims parameter JSON string
  # Per OIDC Core §5.5: The claims parameter is a JSON object containing
  # id_token and/or userinfo keys, each mapping to claim requests
  def parse_claims_parameter(claims_string)
    return {} if claims_string.blank?
    return nil if claims_string.length > 4096

    parsed = JSON.parse(claims_string)
    return nil unless parsed.is_a?(Hash)

    # Validate structure: can have id_token, userinfo, or both
    valid_keys = parsed.keys & ["id_token", "userinfo"]
    return nil if valid_keys.empty?

    # Validate each claim request has proper structure
    valid_keys.each do |key|
      next unless parsed[key].is_a?(Hash)

      parsed[key].each do |_claim_name, claim_spec|
        # Claim spec can be null (requested), true (essential), or a hash with specific keys
        next if claim_spec.nil? || claim_spec == true || claim_spec == false
        next if claim_spec.is_a?(Hash) && claim_spec.keys.all? { |k| ["essential", "value", "values"].include?(k) }

        # Invalid claim specification
        return nil
      end
    end

    parsed
  rescue JSON::ParserError
    nil
  end

  # Validate that requested claims are covered by granted scopes
  # Per OIDC Core §5.5: Claims can only be requested if the corresponding scope is granted
  def validate_claims_against_scopes(parsed_claims, granted_scopes)
    granted = Array(granted_scopes).map(&:to_s)
    errors = []

    # Standard claim-to-scope mapping
    claim_scope_mapping = {
      "email" => "email",
      "email_verified" => "email",
      "preferred_username" => "profile",
      "name" => "profile",
      "updated_at" => "profile",
      "groups" => "groups"
    }

    # Check both id_token and userinfo claims
    ["id_token", "userinfo"].each do |context|
      next unless parsed_claims[context]&.is_a?(Hash)

      parsed_claims[context].each do |claim_name, _claim_spec|
        # Skip custom claims (not in standard mapping)
        # Custom claims are allowed since they're configured in the IdP
        next unless claim_scope_mapping.key?(claim_name)

        required_scope = claim_scope_mapping[claim_name]
        unless granted.include?(required_scope)
          errors << "#{claim_name} requires #{required_scope} scope"
        end
      end
    end

    if errors.any?
      {valid: false, errors: errors}
    else
      {valid: true}
    end
  end

  # Check if claims match existing consent
  # For MVP: treat any claims request as requiring new consent if consent has no claims stored
  def claims_match_consent?(parsed_claims, consent)
    return true if parsed_claims.nil? || parsed_claims.empty?

    # If consent has no claims stored, this is a new claims request
    # Require fresh consent
    return false if consent.parsed_claims_requests.empty?

    # If both have claims, they must match exactly
    consent.parsed_claims_requests == parsed_claims
  end

  # Check if a claim should be included in UserInfo response
  # Returns true if no claims filtering or claim is explicitly requested
  def should_include_claim_for_userinfo?(claim_name, userinfo_claims)
    return true if userinfo_claims.empty?
    userinfo_claims.key?(claim_name)
  end

  # Filter custom claims for UserInfo endpoint
  # Removes claims not explicitly requested
  # Applies value/values filtering if specified
  def filter_custom_claims_for_userinfo(claims, userinfo_claims)
    # Get all claim names that are NOT standard OIDC claims
    standard_claims = %w[sub email email_verified name preferred_username updated_at groups]
    custom_claim_names = claims.keys.map(&:to_s) - standard_claims

    filtered = claims.dup

    custom_claim_names.each do |claim_name|
      claim_sym = claim_name.to_sym

      unless userinfo_claims.key?(claim_name) || userinfo_claims.key?(claim_sym)
        filtered.delete(claim_sym)
        next
      end

      # Apply value/values filtering if specified
      claim_spec = userinfo_claims[claim_name] || userinfo_claims[claim_sym]
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
