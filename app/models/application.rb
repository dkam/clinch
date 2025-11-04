class Application < ApplicationRecord
  has_secure_password :client_secret, validations: false

  has_many :application_groups, dependent: :destroy
  has_many :allowed_groups, through: :application_groups, source: :group
  has_many :oidc_authorization_codes, dependent: :destroy
  has_many :oidc_access_tokens, dependent: :destroy
  has_many :oidc_user_consents, dependent: :destroy

  validates :name, presence: true
  validates :slug, presence: true, uniqueness: { case_sensitive: false },
                  format: { with: /\A[a-z0-9\-]+\z/, message: "only lowercase letters, numbers, and hyphens" }
  validates :app_type, presence: true,
                      inclusion: { in: %w[oidc forward_auth] }
  validates :client_id, uniqueness: { allow_nil: true }
  validates :client_secret, presence: true, if: -> { oidc? && new_record? }
  validates :domain_pattern, presence: true, uniqueness: { case_sensitive: false }, if: :forward_auth?
  validates :landing_url, format: { with: URI::regexp(%w[http https]), allow_nil: true, message: "must be a valid URL" }

  normalizes :slug, with: ->(slug) { slug.strip.downcase }
  normalizes :domain_pattern, with: ->(pattern) { pattern&.strip&.downcase }

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

  private

  def generate_client_credentials
    self.client_id ||= SecureRandom.urlsafe_base64(32)
    # Generate and hash the client secret
    if new_record? && client_secret.blank?
      secret = SecureRandom.urlsafe_base64(48)
      self.client_secret = secret
    end
  end
end
