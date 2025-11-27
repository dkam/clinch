class Application < ApplicationRecord
  has_secure_password :client_secret, validations: false

  has_one_attached :icon

  # Fix SVG content type after attachment
  after_save :fix_icon_content_type, if: -> { icon.attached? && saved_change_to_attribute?(:id) == false }

  has_many :application_groups, dependent: :destroy
  has_many :allowed_groups, through: :application_groups, source: :group
  has_many :application_user_claims, dependent: :destroy
  has_many :oidc_authorization_codes, dependent: :destroy
  has_many :oidc_access_tokens, dependent: :destroy
  has_many :oidc_refresh_tokens, dependent: :destroy
  has_many :oidc_user_consents, dependent: :destroy

  validates :name, presence: true
  validates :slug, presence: true, uniqueness: { case_sensitive: false },
                  format: { with: /\A[a-z0-9\-]+\z/, message: "only lowercase letters, numbers, and hyphens" }
  validates :app_type, presence: true,
                      inclusion: { in: %w[oidc forward_auth] }
  validates :client_id, uniqueness: { allow_nil: true }
  validates :client_secret, presence: true, on: :create, if: -> { oidc? }
  validates :domain_pattern, presence: true, uniqueness: { case_sensitive: false }, if: :forward_auth?
  validates :landing_url, format: { with: URI::regexp(%w[http https]), allow_nil: true, message: "must be a valid URL" }
  validates :backchannel_logout_uri, format: {
    with: URI::regexp(%w[http https]),
    allow_nil: true,
    message: "must be a valid HTTP or HTTPS URL"
  }
  validate :backchannel_logout_uri_must_be_https_in_production, if: -> { backchannel_logout_uri.present? }

  # Icon validation using ActiveStorage validators
  validate :icon_validation, if: -> { icon.attached? }

  # Token TTL validations (for OIDC apps)
  validates :access_token_ttl, numericality: { greater_than_or_equal_to: 300, less_than_or_equal_to: 86400 }, if: :oidc?  # 5 min - 24 hours
  validates :refresh_token_ttl, numericality: { greater_than_or_equal_to: 86400, less_than_or_equal_to: 7776000 }, if: :oidc?  # 1 day - 90 days
  validates :id_token_ttl, numericality: { greater_than_or_equal_to: 300, less_than_or_equal_to: 86400 }, if: :oidc?  # 5 min - 24 hours

  normalizes :slug, with: ->(slug) { slug.strip.downcase }
  normalizes :domain_pattern, with: ->(pattern) {
    normalized = pattern&.strip&.downcase
    normalized.blank? ? nil : normalized
  }

  before_validation :generate_client_credentials, on: :create, if: :oidc?

  # Default header configuration for ForwardAuth
  DEFAULT_HEADERS = {
    user: 'X-Remote-User',
    email: 'X-Remote-Email',
    name: 'X-Remote-Name',
    groups: 'X-Remote-Groups',
    admin: 'X-Remote-Admin'
  }.freeze

  # Scopes
  scope :active, -> { where(active: true) }
  scope :oidc, -> { where(app_type: "oidc") }
  scope :forward_auth, -> { where(app_type: "forward_auth") }
  scope :ordered, -> { order(domain_pattern: :asc) }

  # Type checks
  def oidc?
    app_type == "oidc"
  end

  def forward_auth?
    app_type == "forward_auth"
  end

  # Access control
  def user_allowed?(user)
    return false unless active?
    return false unless user.active?

    # If no groups are specified, allow all active users
    return true if allowed_groups.empty?

    # Otherwise, user must be in at least one of the allowed groups
    (user.groups & allowed_groups).any?
  end

  # OIDC helpers
  def parsed_redirect_uris
    return [] unless redirect_uris.present?
    JSON.parse(redirect_uris)
  rescue JSON::ParserError
    redirect_uris.split("\n").map(&:strip).reject(&:blank?)
  end

  def parsed_metadata
    return {} unless metadata.present?
    JSON.parse(metadata)
  rescue JSON::ParserError
    {}
  end

  # ForwardAuth helpers
  def parsed_headers_config
    return {} unless headers_config.present?
    headers_config.is_a?(Hash) ? headers_config : JSON.parse(headers_config)
  rescue JSON::ParserError
    {}
  end

  # Check if a domain matches this application's pattern (for ForwardAuth)
  def matches_domain?(domain)
    return false if domain.blank? || !forward_auth?

    pattern = domain_pattern.gsub('.', '\.')
    pattern = pattern.gsub('*', '[^.]*')

    regex = Regexp.new("^#{pattern}$", Regexp::IGNORECASE)
    regex.match?(domain.downcase)
  end

  # Policy determination based on user status (for ForwardAuth)
  def policy_for_user(user)
    return 'deny' unless active?
    return 'deny' unless user.active?

    # If no groups specified, bypass authentication
    return 'bypass' if allowed_groups.empty?

    # If user is in allowed groups, determine auth level
    if user_allowed?(user)
      # Require 2FA if user has TOTP configured, otherwise one factor
      user.totp_enabled? ? 'two_factor' : 'one_factor'
    else
      'deny'
    end
  end

  # Get effective header configuration (for ForwardAuth)
  def effective_headers
    DEFAULT_HEADERS.merge(parsed_headers_config.symbolize_keys)
  end

  # Generate headers for a specific user (for ForwardAuth)
  def headers_for_user(user)
    headers = {}
    effective = effective_headers

    # Only generate headers that are configured (not set to nil/false)
    effective.each do |key, header_name|
      next unless header_name.present?  # Skip disabled headers

      case key
      when :user, :email
        headers[header_name] = user.email_address
      when :name
        headers[header_name] = user.name.presence || user.email_address
      when :groups
        headers[header_name] = user.groups.pluck(:name).join(",") if user.groups.any?
      when :admin
        headers[header_name] = user.admin? ? "true" : "false"
      end
    end

    headers
  end

  # Check if all headers are disabled (for ForwardAuth)
  def headers_disabled?
    headers_config.present? && effective_headers.values.all?(&:blank?)
  end

  # Generate and return a new client secret
  def generate_new_client_secret!
    secret = SecureRandom.urlsafe_base64(48)
    self.client_secret = secret
    self.save!
    secret
  end

  # Token TTL helper methods (for OIDC)
  def access_token_expiry
    (access_token_ttl || 3600).seconds.from_now
  end

  def refresh_token_expiry
    (refresh_token_ttl || 2592000).seconds.from_now
  end

  def id_token_expiry_seconds
    id_token_ttl || 3600
  end

  # Human-readable TTL for display
  def access_token_ttl_human
    duration_to_human(access_token_ttl || 3600)
  end

  def refresh_token_ttl_human
    duration_to_human(refresh_token_ttl || 2592000)
  end

  def id_token_ttl_human
    duration_to_human(id_token_ttl || 3600)
  end

  # Get app-specific custom claims for a user
  def custom_claims_for_user(user)
    app_claim = application_user_claims.find_by(user: user)
    app_claim&.parsed_custom_claims || {}
  end

  # Check if this application supports backchannel logout
  def supports_backchannel_logout?
    backchannel_logout_uri.present?
  end

  # Check if a user has an active session with this application
  # (i.e., has valid, non-revoked tokens)
  def user_has_active_session?(user)
    oidc_access_tokens.where(user: user).valid.exists? ||
    oidc_refresh_tokens.where(user: user).valid.exists?
  end

  private

  def fix_icon_content_type
    return unless icon.attached?

    # Fix SVG content type if it was detected incorrectly
    if icon.filename.extension == "svg" && icon.content_type == "application/octet-stream"
      icon.blob.update(content_type: "image/svg+xml")
    end
  end

  def icon_validation
    return unless icon.attached?

    # Check content type
    allowed_types = ['image/png', 'image/jpg', 'image/jpeg', 'image/gif', 'image/svg+xml']
    unless allowed_types.include?(icon.content_type)
      errors.add(:icon, 'must be a PNG, JPG, GIF, or SVG image')
    end

    # Check file size (2MB limit)
    if icon.blob.byte_size > 2.megabytes
      errors.add(:icon, 'must be less than 2MB')
    end
  end

  def duration_to_human(seconds)
    if seconds < 3600
      "#{seconds / 60} minutes"
    elsif seconds < 86400
      "#{seconds / 3600} hours"
    else
      "#{seconds / 86400} days"
    end
  end

  def generate_client_credentials
    self.client_id ||= SecureRandom.urlsafe_base64(32)
    # Generate and hash the client secret
    if new_record? && client_secret.blank?
      secret = SecureRandom.urlsafe_base64(48)
      self.client_secret = secret
    end
  end

  def backchannel_logout_uri_must_be_https_in_production
    return unless Rails.env.production?
    return unless backchannel_logout_uri.present?

    begin
      uri = URI.parse(backchannel_logout_uri)
      unless uri.scheme == 'https'
        errors.add(:backchannel_logout_uri, 'must use HTTPS in production')
      end
    rescue URI::InvalidURIError
      # Let the format validator handle invalid URIs
    end
  end
end
