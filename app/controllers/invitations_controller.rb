class InvitationsController < ApplicationController
  include Authentication
  allow_unauthenticated_access
  before_action :set_user_by_invitation_token, only: %i[ show update ]

  def show
    # Show the password setup form
  end

  def update
    # Validate password manually since empty passwords might not trigger validation
    password = params[:password]
    password_confirmation = params[:password_confirmation]

    if password.blank? || password_confirmation.blank? || password != password_confirmation || password.length < 8
      redirect_to invitation_path(params[:token]), alert: "Passwords did not match."
      return
    end

    if @user.update(password: password, password_confirmation: password_confirmation)
      @user.update!(status: :active)
      @user.sessions.destroy_all
      start_new_session_for @user
      redirect_to root_path, notice: "Your account has been set up successfully. Welcome!"
    else
      redirect_to invitation_path(params[:token]), alert: "Passwords did not match."
    end
  end

  private

  def set_user_by_invitation_token
    @user = User.find_by_token_for(:invitation_login, params[:token])

    # Check if user is still pending invitation
    if @user.nil?
      redirect_to signin_path, alert: "Invitation link is invalid or has expired."
      return false
    elsif @user.pending_invitation?
      # User is valid and pending - proceed
      return true
    else
      redirect_to signin_path, alert: "This invitation has already been used or is no longer valid."
      return false
    end
  rescue ActiveSupport::MessageVerifier::InvalidSignature
    redirect_to signin_path, alert: "Invitation link is invalid or has expired."
    return false
  end
end