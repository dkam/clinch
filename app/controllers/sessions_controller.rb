class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create verify_totp ]
  rate_limit to: 20, within: 3.minutes, only: :create, with: -> { redirect_to signin_path, alert: "Too many attempts. Try again later." }
  rate_limit to: 10, within: 3.minutes, only: :verify_totp, with: -> { redirect_to totp_verification_path, alert: "Too many attempts. Try again later." }

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
    redirect_to profile_path, notice: "Session revoked successfully."
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
