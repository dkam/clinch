class SecurityMailer < ApplicationMailer
  SUBJECT_PREFIX = "[Clinch security alert] ".freeze

  def password_changed(user, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    mail subject: "#{SUBJECT_PREFIX}Your password was changed", to: user.email_address
  end

  def totp_disabled(user, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    mail subject: "#{SUBJECT_PREFIX}Two-factor authentication was disabled", to: user.email_address
  end

  def backup_codes_regenerated(user, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    mail subject: "#{SUBJECT_PREFIX}Two-factor backup codes were regenerated", to: user.email_address
  end

  def passkey_added(user, nickname:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @nickname = nickname
    mail subject: "#{SUBJECT_PREFIX}A passkey was added to your account", to: user.email_address
  end

  def passkey_removed(user, nickname:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @nickname = nickname
    mail subject: "#{SUBJECT_PREFIX}A passkey was removed from your account", to: user.email_address
  end

  def api_key_created(user, name:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @api_key_name = name
    mail subject: "#{SUBJECT_PREFIX}An API key was created on your account", to: user.email_address
  end

  def api_key_revoked(user, name:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @api_key_name = name
    mail subject: "#{SUBJECT_PREFIX}An API key was revoked on your account", to: user.email_address
  end

  def suspicious_passkey_used(user, nickname:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @nickname = nickname
    mail subject: "#{SUBJECT_PREFIX}A passkey sign-in was blocked", to: user.email_address
  end

  def email_address_changed(user, recipient:, old_email:, new_email:, ip:, user_agent:, occurred_at:)
    assign_context(user, ip, user_agent, occurred_at)
    @recipient = recipient
    @old_email = old_email
    @new_email = new_email
    mail subject: "#{SUBJECT_PREFIX}Your account email address was changed", to: recipient
  end

  private

  def assign_context(user, ip, user_agent, occurred_at)
    @user = user
    @ip = ip
    @user_agent = user_agent
    @occurred_at = occurred_at
  end
end
