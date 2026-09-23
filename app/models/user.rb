class User < ApplicationRecord
  # Encrypt TOTP secrets at rest (key derived from SECRET_KEY_BASE)
  encrypts :totp_secret

  has_secure_password
  has_many :sessions, dependent: :destroy
  has_many :user_groups, dependent: :destroy
  has_many :groups, through: :user_groups
  has_many :application_user_claims, dependent: :destroy
  has_many :oidc_user_consents, dependent: :destroy
  has_many :oidc_pairwise_subjects, dependent: :delete_all
  has_many :webauthn_credentials, dependent: :destroy
  has_many :api_keys, dependent: :destroy
  has_many :oidc_access_tokens
  has_many :oidc_refresh_tokens
  has_many :oidc_authorization_codes
  has_many :oidc_device_codes

  # Token generation for passwordless flows
  generates_token_for :invitation_login, expires_in: 24.hours do
    updated_at
  end

  generates_token_for :password_reset, expires_in: 1.hour do
    updated_at
  end

  # Proves control of email_awaiting_confirmation. Bound to the address pair and
  # the verified state, so a link stops working once it has been used, once a
  # newer change replaces the pending address, or once the address moves on.
  generates_token_for :email_confirmation, expires_in: 24.hours do
    [email_address, unconfirmed_email, email_verified_at&.to_i]
  end

  normalizes :email_address, with: ->(e) { e.strip.downcase }
  normalizes :unconfirmed_email, with: ->(e) { e.strip.downcase }
  normalizes :username, with: ->(u) { u.strip.downcase if u.present? }

  # Reserved OIDC claim names that should not be overridden
  RESERVED_CLAIMS = %w[
    iss sub aud exp iat nbf jti nonce azp
    email email_verified preferred_username name
    groups
  ].freeze

  validates :email_address, presence: true, uniqueness: {case_sensitive: false},
    format: {with: URI::MailTo::EMAIL_REGEXP}
  validates :username, uniqueness: {case_sensitive: false}, allow_nil: true,
    format: {with: /\A[a-zA-Z0-9_-]+\z/, message: "can only contain letters, numbers, underscores, and hyphens"},
    length: {minimum: 2, maximum: 30}
  validates :password, length: {minimum: 8}, allow_nil: true
  validate :no_reserved_claim_names
  validate :unconfirmed_email_is_usable, if: -> { unconfirmed_email.present? && will_save_change_to_unconfirmed_email? }

  # An address set by anything other than confirmation is unproven. Doing this
  # on save rather than in each controller means no path — admin edit, console,
  # a future API — can change the address and leave it marked verified.
  before_save :unverify_changed_email

  # Enum - automatically creates scopes (User.active, User.disabled, etc.)
  enum :status, {active: 0, disabled: 1, pending_invitation: 2}

  # When an account stops being active (e.g. an admin disables it), immediately
  # terminate its sessions so access is revoked everywhere, not just on expiry.
  # Defence-in-depth: session lookup also filters by active status at request time.
  after_update_commit :revoke_sessions_when_deactivated

  # Scopes
  scope :admins, -> { joins(:groups).where(groups: {admin: true}).distinct }

  # Set true on a user (or on the user_params) to skip the auto-assign callback
  # for that record. Used by the admin invite form (opt-out checkbox) and by
  # tests that want a clean slate.
  attr_accessor :skip_auto_assign

  after_create :add_to_auto_assign_groups, unless: :skip_auto_assign

  def admin?
    groups.any?(&:admin?)
  end

  # What relying parties are told as `email_verified`. Relying parties link and
  # provision accounts on it, so it is only true once the address has followed
  # a link sent to it (an invitation or a confirmation).
  def email_verified?
    email_verified_at.present?
  end

  # The address a confirmation link would prove: a pending change, or the
  # current address while it is unverified. Nil when there is nothing to prove.
  def email_awaiting_confirmation
    unconfirmed_email.presence || (email_address unless email_verified?)
  end

  # Holds a self-service change until the new address confirms it. The account
  # keeps its current address — for sign-in, resets and every relying party —
  # until then.
  def request_email_change(new_email)
    self.unconfirmed_email = new_email
    save
  end

  # Called when a confirmation link is followed. Validation re-checks that the
  # address is still free, since another account may have taken it since.
  def confirm_email
    update(
      email_address: unconfirmed_email.presence || email_address,
      unconfirmed_email: nil,
      email_verified_at: Time.current
    )
  end

  # TOTP methods
  def totp_enabled?
    totp_secret.present?
  end

  def enable_totp!
    require "rotp"
    self.totp_secret = ROTP::Base32.random
    # generate_backup_codes assigns the BCrypt hashes to self.backup_codes and
    # returns the plaintext codes for display. Do NOT reassign backup_codes to the
    # return value — that would store the plaintext codes and break verification.
    generate_backup_codes
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
    # Pass `after:` so a code can only be accepted once: ROTP rejects any timestep
    # at or before the last accepted one, closing the ~90s drift-window replay.
    verified_at = totp.verify(code, drift_behind: 30, drift_ahead: 30, after: last_otp_at)
    return false unless verified_at

    update_column(:last_otp_at, verified_at)
    true
  end

  # Console/debug helper: get current TOTP code
  def console_totp
    return nil unless totp_enabled?

    require "rotp"
    ROTP::TOTP.new(totp_secret).now
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
      Rails.logger.info "Backup code used successfully - User ID: #{id}, IP: #{Current.session&.ip_address}"
      true
    else
      # Increment failed attempt counter and log for security monitoring
      increment_backup_code_failed_attempts
      Rails.logger.warn "Failed backup code attempt - User ID: #{id}, IP: #{Current.session&.ip_address}"
      false
    end
  end

  # Rate limiting for backup code verification to prevent brute force attacks
  def rate_limit_backup_code_verification?
    # Use Rails.cache to track failed attempts
    cache_key = "backup_code_failed_attempts_#{id}"
    attempts = Rails.cache.read(cache_key) || 0

    attempts >= 5
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

  def add_to_auto_assign_groups
    Group.auto_assign.each { |g| groups << g }
  end

  # Disabling an account is the admin's emergency lever, so it must cut off every
  # credential the account holds — not just browser sessions. OIDC access and
  # refresh tokens are checked against the user at use time (userinfo,
  # introspection), but revoking them here means relying parties that cache
  # nothing still see the cutoff immediately, and it closes the window for any
  # future consumer that forgets the check.
  def revoke_sessions_when_deactivated
    return unless saved_change_to_status?
    return if active?

    now = Time.current

    sessions.destroy_all
    oidc_access_tokens.where(revoked_at: nil).update_all(revoked_at: now)
    oidc_refresh_tokens.where(revoked_at: nil).update_all(revoked_at: now)
    api_keys.where(revoked_at: nil).update_all(revoked_at: now)

    # Pending grants have not been exchanged for tokens yet; delete them so a
    # code issued moments before deactivation cannot still be redeemed.
    oidc_authorization_codes.where(used: false).delete_all

    # Device codes are deliberately not touched here. A *pending* code has no
    # user_id yet (OidcDeviceCode: `belongs_to :user, optional: true`), so it is
    # not reachable through this association at all; an *approved* one is, but
    # deleting it would only duplicate the check the device grant already makes
    # at redemption — oidc_controller#device_code_grant re-runs
    # `application.user_allowed?(user)`, which covers user.active?, so a code
    # approved before deactivation cannot be exchanged for tokens afterwards.
  end

  def unconfirmed_email_is_usable
    if !URI::MailTo::EMAIL_REGEXP.match?(unconfirmed_email)
      errors.add(:email_address, "is invalid")
    elsif unconfirmed_email == email_address
      errors.add(:email_address, "is already your address")
    elsif User.where(email_address: unconfirmed_email).where.not(id: id).exists?
      errors.add(:email_address, "has already been taken")
    end
  end

  def unverify_changed_email
    return unless will_save_change_to_email_address?
    return if will_save_change_to_email_verified_at?

    self.email_verified_at = nil
    # A pending change was made against the old address; it no longer applies.
    self.unconfirmed_email = nil unless will_save_change_to_unconfirmed_email?
  end

  def no_reserved_claim_names
    return if custom_claims.blank?

    reserved_used = parsed_custom_claims.keys.map(&:to_s) & RESERVED_CLAIMS
    if reserved_used.any?
      errors.add(:custom_claims, "cannot override reserved OIDC claims: #{reserved_used.join(", ")}")
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
