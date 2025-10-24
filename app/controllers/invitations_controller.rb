class InvitationsController < ApplicationController
  allow_unauthenticated_access
  before_action :set_user_by_invitation_token, only: %i[ show update ]

  def show
    # Show the password setup form
  end

  def update
    if @user.update(params.permit(:password, :password_confirmation))
      @user.update!(status: :active)
      @user.sessions.destroy_all
      redirect_to new_session_path, notice: "Your account has been set up successfully. Please sign in."
    else
      redirect_to invite_path(params[:token]), alert: "Passwords did not match."
    end
  end

  private

  def set_user_by_invitation_token
    @user = User.find_by_invitation_login_token!(params[:token])

    # Check if user is still pending invitation
    unless @user.pending_invitation?
      redirect_to new_session_path, alert: "This invitation has already been used or is no longer valid."
    end
  rescue ActiveSupport::MessageVerifier::InvalidSignature
    redirect_to new_session_path, alert: "Invitation link is invalid or has expired."
  end
end