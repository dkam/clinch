class ProfilesController < ApplicationController
  def show
    @user = Current.session.user
    @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
  end

  def update
    @user = Current.session.user

    if params[:user][:password].present?
      # Updating password - requires current password
      unless @user.authenticate(params[:user][:current_password])
        @user.errors.add(:current_password, "is incorrect")
        @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
        render :show, status: :unprocessable_entity
        return
      end

      if @user.update(password_params)
        redirect_to profile_path, notice: "Password updated successfully."
      else
        @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
        render :show, status: :unprocessable_entity
      end
    else
      # Updating email
      if @user.update(email_params)
        redirect_to profile_path, notice: "Email updated successfully."
      else
        @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
        render :show, status: :unprocessable_entity
      end
    end
  end

  private

  def email_params
    params.require(:user).permit(:email_address)
  end

  def password_params
    params.require(:user).permit(:password, :password_confirmation)
  end
end
