class ProfilesController < ApplicationController
  def show
    @user = Current.session.user
    @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
    @connected_applications = @user.oidc_user_consents.includes(:application).order(granted_at: :desc)
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

  def revoke_consent
    @user = Current.session.user
    application = Application.find(params[:application_id])

    # Check if user has consent for this application
    consent = @user.oidc_user_consents.find_by(application: application)
    unless consent
      redirect_to profile_path, alert: "No consent found for this application."
      return
    end

    # Revoke the consent
    consent.destroy
    redirect_to profile_path, notice: "Successfully revoked access to #{application.name}."
  end

  def revoke_all_consents
    @user = Current.session.user
    count = @user.oidc_user_consents.count

    if count > 0
      @user.oidc_user_consents.destroy_all
      redirect_to profile_path, notice: "Successfully revoked access to #{count} applications."
    else
      redirect_to profile_path, alert: "No applications to revoke."
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
