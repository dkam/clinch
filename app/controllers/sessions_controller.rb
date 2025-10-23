class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create verify_totp ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to signin_path, alert: "Too many attempts. Try again later." }
  rate_limit to: 5, within: 3.minutes, only: :verify_totp, with: -> { redirect_to totp_verification_path, alert: "Too many attempts. Try again later." }

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

    # Check if user is active
    unless user.status == "active"
      redirect_to signin_path, alert: "Your account is not active. Please contact an administrator."
      return
    end

    # Check if TOTP is required
    if user.totp_enabled?
      # Store user ID in session temporarily for TOTP verification
      session[:pending_totp_user_id] = user.id
      redirect_to totp_verification_path
      return
    end

    # Sign in successful
    start_new_session_for user
    redirect_to after_authentication_url, notice: "Signed in successfully."
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

      # Try TOTP verification first
      if user.verify_totp(code)
        session.delete(:pending_totp_user_id)
        start_new_session_for user
        redirect_to after_authentication_url, notice: "Signed in successfully."
        return
      end

      # Try backup code verification
      if user.verify_backup_code(code)
        session.delete(:pending_totp_user_id)
        start_new_session_for user
        redirect_to after_authentication_url, notice: "Signed in successfully using backup code."
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
end
