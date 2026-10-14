# Confirms the signed-in user's password before something that adds a way into
# their account. See RecentAuthentication.
class ReauthenticationsController < ApplicationController
  def new
  end

  def create
    user = Current.session.user

    # The same per-account budget as signing in: both are guesses at one password.
    if SignInThrottle.blocked?(:password, user.email_address)
      flash.now[:alert] = SessionsController::THROTTLED_MESSAGE
      render :new, status: :unprocessable_entity
      return
    end

    if user.authenticate(params[:password].to_s)
      SignInThrottle.clear(:password, user.email_address)
      note_authentication
      redirect_to session.delete(:return_to_after_reauthenticating) || root_path
    else
      SignInThrottle.record_failure(:password, user.email_address)
      flash.now[:alert] = "Incorrect password."
      render :new, status: :unprocessable_entity
    end
  end
end
