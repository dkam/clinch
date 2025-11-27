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

    # Send backchannel logout notification before revoking consent
    if application.supports_backchannel_logout?
      BackchannelLogoutJob.perform_later(
        user_id: @user.id,
        application_id: application.id,
        consent_sid: consent.sid
      )
      Rails.logger.info "ActiveSessionsController: Enqueued backchannel logout for #{application.name}"
    end

    # Revoke all tokens for this user-application pair
    now = Time.current
    revoked_access_tokens = OidcAccessToken.where(application: application, user: @user, revoked_at: nil)
                                           .update_all(revoked_at: now)
    revoked_refresh_tokens = OidcRefreshToken.where(application: application, user: @user, revoked_at: nil)
                                             .update_all(revoked_at: now)

    Rails.logger.info "ActiveSessionsController: Revoked #{revoked_access_tokens} access tokens and #{revoked_refresh_tokens} refresh tokens for #{application.name}"

    # Revoke the consent
    consent.destroy
    redirect_to active_sessions_path, notice: "Successfully revoked access to #{application.name}."
  end

  def logout_from_app
    @user = Current.session.user
    application = Application.find(params[:application_id])

    # Check if user has consent for this application
    consent = @user.oidc_user_consents.find_by(application: application)
    unless consent
      redirect_to root_path, alert: "No active session found for this application."
      return
    end

    # Send backchannel logout notification
    if application.supports_backchannel_logout?
      BackchannelLogoutJob.perform_later(
        user_id: @user.id,
        application_id: application.id,
        consent_sid: consent.sid
      )
      Rails.logger.info "ActiveSessionsController: Enqueued backchannel logout for #{application.name}"
    end

    # Revoke all tokens for this user-application pair
    now = Time.current
    revoked_access_tokens = OidcAccessToken.where(application: application, user: @user, revoked_at: nil)
                                           .update_all(revoked_at: now)
    revoked_refresh_tokens = OidcRefreshToken.where(application: application, user: @user, revoked_at: nil)
                                             .update_all(revoked_at: now)

    Rails.logger.info "ActiveSessionsController: Logged out from #{application.name} - revoked #{revoked_access_tokens} access tokens and #{revoked_refresh_tokens} refresh tokens"

    # Keep the consent intact - this is the key difference from revoke_consent
    redirect_to root_path, notice: "Successfully logged out of #{application.name}."
  end

  def revoke_all_consents
    @user = Current.session.user
    consents = @user.oidc_user_consents.includes(:application)
    count = consents.count

    if count > 0
      # Send backchannel logout notifications before revoking consents
      consents.each do |consent|
        next unless consent.application.supports_backchannel_logout?

        BackchannelLogoutJob.perform_later(
          user_id: @user.id,
          application_id: consent.application.id,
          consent_sid: consent.sid
        )
      end
      Rails.logger.info "ActiveSessionsController: Enqueued #{count} backchannel logout notifications"

      @user.oidc_user_consents.destroy_all
      redirect_to active_sessions_path, notice: "Successfully revoked access to #{count} applications."
    else
      redirect_to active_sessions_path, alert: "No applications to revoke."
    end
  end
end