class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to signin_path, alert: "Too many attempts. Try again later." }

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
      # TODO: Implement TOTP verification flow
      # For now, reject login if TOTP is enabled
      redirect_to signin_path, alert: "Two-factor authentication is enabled but not yet implemented. Please contact an administrator."
      return
    end

    # Sign in successful
    start_new_session_for user
    redirect_to after_authentication_url, notice: "Signed in successfully."
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
