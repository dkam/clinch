class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  has_many :user_groups, dependent: :destroy
  has_many :groups, through: :user_groups
  has_many :oidc_user_consents, dependent: :destroy

  # Token generation for passwordless flows
  generates_token_for :invitation_login, expires_in: 24.hours do
    updated_at
  end

  generates_token_for :password_reset, expires_in: 1.hour do
    updated_at
  end

  generates_token_for :magic_login, expires_in: 15.minutes do
    last_sign_in_at
  end

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  validates :email_address, presence: true, uniqueness: { case_sensitive: false },
                           format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :password, length: { minimum: 8 }, allow_nil: true

  # Enum - automatically creates scopes (User.active, User.disabled, etc.)
  enum :status, { active: 0, disabled: 1, pending_invitation: 2 }

  # Scopes
  scope :admins, -> { where(admin: true) }

  # TOTP methods
  def totp_enabled?
    totp_secret.present?
  end

  def enable_totp!
    require "rotp"
    self.totp_secret = ROTP::Base32.random
    self.backup_codes = generate_backup_codes
    save!
  end

  def disable_totp!
    update!(totp_secret: nil, totp_required: false, backup_codes: nil)
  end

  def totp_provisioning_uri(issuer: "Clinch")
    return nil unless totp_enabled?

    require "rotp"
    totp = ROTP::TOTP.new(totp_secret, issuer: issuer)
    totp.provisioning_uri(email_address)
  end

  def verify_totp(code)
    return false unless totp_enabled?

    require "rotp"
    totp = ROTP::TOTP.new(totp_secret)
    totp.verify(code, drift_behind: 30, drift_ahead: 30)
  end

  def verify_backup_code(code)
    return false unless backup_codes.present?

    codes = JSON.parse(backup_codes)
    if codes.include?(code)
      codes.delete(code)
      update(backup_codes: codes.to_json)
      true
    else
      false
    end
  end

  def parsed_backup_codes
    return [] unless backup_codes.present?
    JSON.parse(backup_codes)
  end

  def has_oidc_consent?(application, requested_scopes)
    oidc_user_consents
      .where(application: application)
      .find { |consent| consent.covers_scopes?(requested_scopes) }
  end

  def revoke_consent!(application)
    consent = oidc_user_consents.find_by(application: application)
    consent&.destroy
  end

  def revoke_all_consents!
    oidc_user_consents.destroy_all
  end

  # Parse custom_claims JSON field
  def parsed_custom_claims
    custom_claims || {}
  end

  private

  def generate_backup_codes
    Array.new(10) { SecureRandom.alphanumeric(8).upcase }.to_json
  end
end
