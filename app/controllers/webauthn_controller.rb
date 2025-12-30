class WebauthnController < ApplicationController
  before_action :set_webauthn_credential, only: [:destroy]
  skip_before_action :require_authentication, only: [:check]

  # Rate limit check endpoint to prevent enumeration attacks
  rate_limit to: 10, within: 1.minute, only: [:check], with: -> {
    render json: { error: "Too many requests. Try again later." }, status: :too_many_requests
  }

  # GET /webauthn/new
  def new
    @webauthn_credential = WebauthnCredential.new
  end

  # POST /webauthn/challenge
  # Generate registration challenge for creating a new passkey
  def challenge
    user = Current.session&.user
    return render json: { error: "Not authenticated" }, status: :unauthorized unless user

    registration_options = WebAuthn::Credential.options_for_create(
      user: {
        id: user.webauthn_user_handle,
        name: user.email_address,
        display_name: user.name || user.email_address
      },
      exclude: user.webauthn_credentials.pluck(:external_id),
      authenticator_selection: {
        userVerification: "preferred",
        residentKey: "preferred",
        authenticatorAttachment: "platform" # Prefer platform authenticators first
      }
    )

    # Store challenge in session for verification
    session[:webauthn_challenge] = registration_options.challenge

    render json: registration_options
  end

  # POST /webauthn/create
  # Verify and store the new credential
  def create
    credential_data, nickname = extract_credential_params

    if credential_data.blank? || nickname.blank?
      render json: { error: "Credential and nickname are required" }, status: :unprocessable_entity
      return
    end

    # Retrieve the challenge from session
    challenge = session.delete(:webauthn_challenge)

    if challenge.blank?
      render json: { error: "Invalid or expired session" }, status: :unprocessable_entity
      return
    end

    begin
      # Pass the credential hash directly to WebAuthn gem
      webauthn_credential = WebAuthn::Credential.from_create(credential_data.to_h)

      # Verify the credential against the challenge
      webauthn_credential.verify(challenge)

      # Extract credential metadata from the hash
      response = credential_data.to_h
      client_extension_results = response["clientExtensionResults"] || {}

      authenticator_type = if response["response"]["authenticatorAttachment"] == "cross-platform"
                            "cross-platform"
                          else
                            "platform"
                          end

      # Determine if this is a backup/synced credential
      backup_eligible = client_extension_results["credProps"]&.dig("rk") || false
      backup_state = client_extension_results["credProps"]&.dig("backup") || false

      # Store the credential
      user = Current.session&.user
      return render json: { error: "Not authenticated" }, status: :unauthorized unless user

      @webauthn_credential = user.webauthn_credentials.create!(
        external_id: Base64.urlsafe_encode64(webauthn_credential.id),
        public_key: Base64.urlsafe_encode64(webauthn_credential.public_key),
        sign_count: webauthn_credential.sign_count,
        nickname: nickname,
        authenticator_type: authenticator_type,
        backup_eligible: backup_eligible,
        backup_state: backup_state
      )

      render json: {
        success: true,
        message: "Passkey '#{nickname}' registered successfully",
        credential_id: @webauthn_credential.id
      }

    rescue WebAuthn::Error => e
      Rails.logger.error "WebAuthn registration error: #{e.message}"
      render json: { error: "Failed to register passkey: #{e.message}" }, status: :unprocessable_entity
    rescue => e
      Rails.logger.error "Unexpected WebAuthn registration error: #{e.class} - #{e.message}"
      render json: { error: "An unexpected error occurred" }, status: :internal_server_error
    end
  end

  # DELETE /webauthn/:id
  # Remove a passkey
  def destroy
    user = Current.session&.user
    return render json: { error: "Not authenticated" }, status: :unauthorized unless user

    if @webauthn_credential.user != user
      render json: { error: "Unauthorized" }, status: :forbidden
      return
    end

    nickname = @webauthn_credential.nickname
    @webauthn_credential.destroy

    respond_to do |format|
      format.html {
        redirect_to profile_path,
        notice: "Passkey '#{nickname}' has been removed"
      }
      format.json {
        render json: {
          success: true,
          message: "Passkey '#{nickname}' has been removed"
        }
      }
    end
  end

  # GET /webauthn/check
  # Check if user has WebAuthn credentials (for login page detection)
  # Security: Returns identical responses for non-existent users to prevent enumeration
  def check
    email = params[:email]&.strip&.downcase

    if email.blank?
      render json: { has_webauthn: false, requires_webauthn: false }
      return
    end

    user = User.find_by(email_address: email)

    # Security: Return identical response for non-existent users
    # Combined with rate limiting (10/min), this prevents account enumeration
    if user.nil?
      render json: { has_webauthn: false, requires_webauthn: false }
      return
    end

    # Only return minimal necessary info - no user_id or preferred_method
    render json: {
      has_webauthn: user.can_authenticate_with_webauthn?,
      requires_webauthn: user.require_webauthn?
    }
  end

  private

  def extract_credential_params
    # Use require.permit which is working and reliable
    # The JavaScript sends params both directly and wrapped in webauthn key
    begin
      # Try direct parameters first
      credential_params = params.require(:credential).permit(:id, :rawId, :type, response: {}, clientExtensionResults: {})
      nickname = params.require(:nickname)
      [credential_params, nickname]
    rescue ActionController::ParameterMissing
      Rails.logger.error("Using the fallback parameters")
      # Fallback to webauthn-wrapped parameters
      webauthn_params = params.require(:webauthn).permit(:nickname, credential: [:id, :rawId, :type, response: {}, clientExtensionResults: {}])
      [webauthn_params[:credential], webauthn_params[:nickname]]
    end
  end

  def set_webauthn_credential
    @webauthn_credential = WebauthnCredential.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    respond_to do |format|
      format.html {
        redirect_to profile_path,
        alert: "Passkey not found"
      }
      format.json {
        render json: { error: "Passkey not found" }, status: :not_found
      }
    end
  end

  # Helper method to convert Base64 to Base64URL if needed
  def base64_to_base64url(str)
    str.gsub('+', '-').gsub('/', '_').gsub(/=+$/, '')
  end

  # Helper method to convert Base64URL to Base64 if needed
  def base64url_to_base64(str)
    str.gsub('-', '+').gsub('_', '/') + '=' * (4 - str.length % 4) % 4
  end
end