class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create verify_totp webauthn_challenge webauthn_verify ]
  rate_limit to: 20, within: 3.minutes, only: :create, with: -> { redirect_to signin_path, alert: "Too many attempts. Try again later." }
  rate_limit to: 10, within: 3.minutes, only: :verify_totp, with: -> { redirect_to totp_verification_path, alert: "Too many attempts. Try again later." }
  rate_limit to: 10, within: 3.minutes, only: [:webauthn_challenge, :webauthn_verify], with: -> { render json: { error: "Too many attempts. Try again later." }, status: :too_many_requests }

  def new
    # Redirect to signup if this is first run
    redirect_to signup_path if User.count.zero?
  end

  def create
    user = User.authenticate_by(params.permit(:email_address, :password))

    if user.nil?
      redirect_to signin_path, alert: "Invalid email address or password."
      return
    end

    # Store the redirect URL from forward auth if present (after validation)
    if params[:rd].present?
      validated_url = validate_redirect_url(params[:rd])
      session[:return_to_after_authenticating] = validated_url if validated_url
    end

    # Check if user is active
    unless user.active?
      if user.pending_invitation?
        redirect_to signin_path, alert: "Please check your email for an invitation to set up your account."
      else
        redirect_to signin_path, alert: "Your account is not active. Please contact an administrator."
      end
      return
    end

    # Check if TOTP is required
    if user.totp_enabled?
      # Store user ID in session temporarily for TOTP verification
      session[:pending_totp_user_id] = user.id
      # Preserve the redirect URL through TOTP verification (after validation)
      if params[:rd].present?
        validated_url = validate_redirect_url(params[:rd])
        session[:totp_redirect_url] = validated_url if validated_url
      end
      redirect_to totp_verification_path(rd: params[:rd])
      return
    end

    # Sign in successful
    start_new_session_for user
    redirect_to after_authentication_url, notice: "Signed in successfully.", allow_other_host: true
  end

  def verify_totp
    # Get the pending user from session
    user_id = session[:pending_totp_user_id]
    unless user_id
      redirect_to signin_path, alert: "Session expired. Please sign in again."
      return
    end

    user = User.find_by(id: user_id)
    unless user
      session.delete(:pending_totp_user_id)
      redirect_to signin_path, alert: "Session expired. Please sign in again."
      return
    end

    # Handle form submission
    if request.post?
      code = params[:code]&.strip

      # Check if user is already authenticated (prevent duplicate submissions)
      if authenticated?
        redirect_to root_path, notice: "Already signed in."
        return
      end

      # Try TOTP verification first
      if user.verify_totp(code)
        session.delete(:pending_totp_user_id)
        # Restore redirect URL if it was preserved
        if session[:totp_redirect_url].present?
          session[:return_to_after_authenticating] = session.delete(:totp_redirect_url)
        end
        start_new_session_for user
        redirect_to after_authentication_url, notice: "Signed in successfully.", allow_other_host: true
        return
      end

      # Try backup code verification
      if user.verify_backup_code(code)
        session.delete(:pending_totp_user_id)
        # Restore redirect URL if it was preserved
        if session[:totp_redirect_url].present?
          session[:return_to_after_authenticating] = session.delete(:totp_redirect_url)
        end
        start_new_session_for user
        redirect_to after_authentication_url, notice: "Signed in successfully using backup code.", allow_other_host: true
        return
      end

      # Invalid code
      redirect_to totp_verification_path, alert: "Invalid verification code. Please try again."
      return
    end

    # Just render the form
  end

  def destroy
    terminate_session
    redirect_to signin_path, status: :see_other, notice: "Signed out successfully."
  end

  def destroy_other
    session = Current.session.user.sessions.find(params[:id])
    session.destroy
    redirect_to active_sessions_path, notice: "Session revoked successfully."
  end

  # WebAuthn authentication methods
  def webauthn_challenge
    email = params[:email]&.strip&.downcase

    if email.blank?
      render json: { error: "Email is required" }, status: :unprocessable_entity
      return
    end

    user = User.find_by(email_address: email)

    if user.nil? || !user.can_authenticate_with_webauthn?
      render json: { error: "User not found or WebAuthn not available" }, status: :unprocessable_entity
      return
    end

    # Store user ID in session for verification
    session[:pending_webauthn_user_id] = user.id

    # Store redirect URL if present
    if params[:rd].present?
      validated_url = validate_redirect_url(params[:rd])
      session[:webauthn_redirect_url] = validated_url if validated_url
    end

    begin
      # Generate authentication options
      # Decode the stored base64url credential IDs before passing to the gem
      credential_ids = user.webauthn_credentials.pluck(:external_id).map do |encoded_id|
        Base64.urlsafe_decode64(encoded_id)
      end

      options = WebAuthn::Credential.options_for_get(
        allow: credential_ids,
        user_verification: "preferred"
      )

      # Store challenge in session
      session[:webauthn_challenge] = options.challenge

      render json: options

    rescue => e
      Rails.logger.error "WebAuthn challenge generation error: #{e.message}"
      render json: { error: "Failed to generate WebAuthn challenge" }, status: :internal_server_error
    end
  end

  def webauthn_verify
    # Get pending user from session
    user_id = session[:pending_webauthn_user_id]
    unless user_id
      render json: { error: "Session expired. Please try again." }, status: :unprocessable_entity
      return
    end

    user = User.find_by(id: user_id)
    unless user
      session.delete(:pending_webauthn_user_id)
      render json: { error: "Session expired. Please try again." }, status: :unprocessable_entity
      return
    end

    # Get the credential and assertion from params
    credential_data = params[:credential]
    if credential_data.blank?
      render json: { error: "Credential data is required" }, status: :unprocessable_entity
      return
    end

    # Get the challenge from session
    challenge = session.delete(:webauthn_challenge)

    if challenge.blank?
      render json: { error: "Invalid or expired session" }, status: :unprocessable_entity
      return
    end

    begin
      # Decode the credential response
      webauthn_credential = WebAuthn::Credential.from_get(credential_data)

      # Find the stored credential
      external_id = Base64.urlsafe_encode64(webauthn_credential.id)
      stored_credential = user.webauthn_credential_for(external_id)

      if stored_credential.nil?
        render json: { error: "Credential not found" }, status: :unprocessable_entity
        return
      end

      # Verify the assertion
      stored_public_key = Base64.urlsafe_decode64(stored_credential.public_key)
      webauthn_credential.verify(
        challenge,
        public_key: stored_public_key,
        sign_count: stored_credential.sign_count
      )

      # Check for suspicious sign count (possible clone)
      if stored_credential.suspicious_sign_count?(webauthn_credential.sign_count)
        Rails.logger.warn "Suspicious WebAuthn sign count for user #{user.id}, credential #{stored_credential.id}"
        # You might want to notify admins or temporarily disable the credential
      end

      # Update credential usage
      stored_credential.update_usage!(
        sign_count: webauthn_credential.sign_count,
        ip_address: request.remote_ip,
        user_agent: request.user_agent
      )

      # Clean up session
      session.delete(:pending_webauthn_user_id)
      if session[:webauthn_redirect_url].present?
        session[:return_to_after_authenticating] = session.delete(:webauthn_redirect_url)
      end

      # Create session
      start_new_session_for user

      render json: {
        success: true,
        redirect_to: after_authentication_url,
        message: "Signed in successfully with passkey"
      }

    rescue WebAuthn::Error => e
      Rails.logger.error "WebAuthn verification error: #{e.message}"
      render json: { error: "Authentication failed: #{e.message}" }, status: :unprocessable_entity
    rescue JSON::ParserError => e
      Rails.logger.error "WebAuthn JSON parsing error: #{e.message}"
      render json: { error: "Invalid credential format" }, status: :unprocessable_entity
    rescue => e
      Rails.logger.error "Unexpected WebAuthn verification error: #{e.class} - #{e.message}"
      render json: { error: "An unexpected error occurred" }, status: :internal_server_error
    end
  end

  private

  def validate_redirect_url(url)
    return nil unless url.present?

    begin
      uri = URI.parse(url)

      # Only allow HTTP/HTTPS schemes
      return nil unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      # Only allow HTTPS in production
      return nil unless Rails.env.development? || uri.scheme == 'https'

      redirect_domain = uri.host.downcase
      return nil unless redirect_domain.present?

      # Check against our ForwardAuthRules
      matching_rule = ForwardAuthRule.active.find do |rule|
        rule.matches_domain?(redirect_domain)
      end

      matching_rule ? url : nil

    rescue URI::InvalidURIError
      nil
    end
  end
end
