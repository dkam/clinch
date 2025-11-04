class ActiveSessionsController < ApplicationController
  def show
    @user = Current.session.user
    @active_sessions = @user.sessions.active.order(last_activity_at: :desc)
    @connected_applications = @user.oidc_user_consents.includes(:application).order(granted_at: :desc)
  end

  def revoke_consent
    @user = Current.session.user
    application = Application.find(params[:application_id])

    # Check if user has consent for this application
    consent = @user.oidc_user_consents.find_by(application: application)
    unless consent
      redirect_to active_sessions_path, alert: "No consent found for this application."
      return
    end

    # Revoke the consent
    consent.destroy
    redirect_to active_sessions_path, notice: "Successfully revoked access to #{application.name}."
  end

  def revoke_all_consents
    @user = Current.session.user
    count = @user.oidc_user_consents.count

    if count > 0
      @user.oidc_user_consents.destroy_all
      redirect_to active_sessions_path, notice: "Successfully revoked access to #{count} applications."
    else
      redirect_to active_sessions_path, alert: "No applications to revoke."
    end
  end
end