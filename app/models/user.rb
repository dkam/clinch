class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  has_many :user_groups, dependent: :destroy
  has_many :groups, through: :user_groups
  has_many :application_user_claims, dependent: :destroy
  has_many :oidc_user_consents, dependent: :destroy
  has_many :webauthn_credentials, dependent: :destroy

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
  normalizes :username, with: ->(u) { u.strip.downcase if u.present? }

  # Reserved OIDC claim names that should not be overridden
  RESERVED_CLAIMS = %w[
    iss sub aud exp iat nbf jti nonce azp
    email email_verified preferred_username name
    groups
  ].freeze

  validates :email_address, presence: true, uniqueness: { case_sensitive: false },
                           format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, uniqueness: { case_sensitive: false }, allow_nil: true,
                      format: { with: /\A[a-zA-Z0-9_-]+\z/, message: "can only contain letters, numbers, underscores, and hyphens" },
                      length: { minimum: 2, maximum: 30 }
  validates :password, length: { minimum: 8 }, allow_nil: true
  validate :no_reserved_claim_names

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
    # Note: This does NOT clear totp_required flag
    # Admins control that flag via admin panel, users cannot remove admin-required 2FA
    update!(totp_secret: nil, backup_codes: nil)
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

    # Rate limiting: prevent brute force attacks on backup codes
    if rate_limit_backup_code_verification?
      Rails.logger.warn "Rate limit exceeded for backup code verification - User ID: #{id}"
      return false
    end

    # backup_codes is now an Array (JSON column), no need to parse
    # Find the matching hash by comparing with BCrypt
    matching_hash = backup_codes.find do |hashed_code|
      BCrypt::Password.new(hashed_code) == code
    end

    if matching_hash
      # Remove the used hash from the array (single-use property)
      backup_codes.delete(matching_hash)
      save! # Save the updated array

      # Log successful backup code usage for security monitoring
      Rails.logger.info "Backup code used successfully - User ID: #{id}, IP: #{Current.session&.client_ip}"
      true
    else
      # Increment failed attempt counter and log for security monitoring
      increment_backup_code_failed_attempts
      Rails.logger.warn "Failed backup code attempt - User ID: #{id}, IP: #{Current.session&.client_ip}"
      false
    end
  end

  # Rate limiting for backup code verification to prevent brute force attacks
  def rate_limit_backup_code_verification?
    # Use Rails.cache to track failed attempts
    cache_key = "backup_code_failed_attempts_#{id}"
    attempts = Rails.cache.read(cache_key) || 0

    if attempts >= 5  # Allow max 5 failed attempts per hour
      true
    else
      # Don't increment here - increment only on failed attempts
      false
    end
  end

  # Increment failed attempt counter
  def increment_backup_code_failed_attempts
    cache_key = "backup_code_failed_attempts_#{id}"
    attempts = Rails.cache.read(cache_key) || 0
    Rails.cache.write(cache_key, attempts + 1, expires_in: 1.hour)
  end

  # WebAuthn methods
  def webauthn_enabled?
    webauthn_credentials.exists?
  end

  def can_authenticate_with_webauthn?
    webauthn_enabled? && active?
  end

  def require_webauthn?
    webauthn_required? || (webauthn_enabled? && !password_digest.present?)
  end

  # Generate stable WebAuthn user handle on first use
  def webauthn_user_handle
    return webauthn_id if webauthn_id.present?

    # Generate random 64-byte opaque identifier (base64url encoded)
    handle = SecureRandom.urlsafe_base64(64)
    update_column(:webauthn_id, handle)
    handle
  end

  def platform_authenticators
    webauthn_credentials.platform_authenticators
  end

  def roaming_authenticators
    webauthn_credentials.roaming_authenticators
  end

  def webauthn_credential_for(external_id)
    webauthn_credentials.find_by(external_id: external_id)
  end

  # Check if user has any backed up (synced) passkeys
  def has_synced_passkeys?
    webauthn_credentials.exists?(backup_eligible: true, backup_state: true)
  end

  # Preferred authentication method for login flow
  def preferred_authentication_method
    return :webauthn if require_webauthn?
    return :webauthn if can_authenticate_with_webauthn? && preferred_2fa_method == "webauthn"
    return :password if password_digest.present?
    :webauthn
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
    return {} if custom_claims.blank?
    custom_claims.is_a?(Hash) ? custom_claims : {}
  end

  # Get fully merged claims for a specific application
  def merged_claims_for_application(application)
    merged = {}

    # Start with group claims (in order)
    groups.each do |group|
      merged.merge!(group.parsed_custom_claims)
    end

    # Merge user global claims
    merged.merge!(parsed_custom_claims)

    # Merge app-specific claims (highest priority)
    merged.merge!(application.custom_claims_for_user(self))

    merged
  end

  private

  def no_reserved_claim_names
    return if custom_claims.blank?

    reserved_used = parsed_custom_claims.keys.map(&:to_s) & RESERVED_CLAIMS
    if reserved_used.any?
      errors.add(:custom_claims, "cannot override reserved OIDC claims: #{reserved_used.join(', ')}")
    end
  end

  def generate_backup_codes
    # Generate plain codes for user to see/save
    plain_codes = Array.new(10) { SecureRandom.alphanumeric(8).upcase }

    # Store BCrypt hashes of the codes
    hashed_codes = plain_codes.map { |code| BCrypt::Password.create(code) }

    # Return plain codes for display (will be shown to user once)
    # Store only hashes in the database (as Array for JSON column)
    self.backup_codes = hashed_codes

    plain_codes
  end
end
