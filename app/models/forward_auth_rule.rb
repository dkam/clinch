class ForwardAuthRule < ApplicationRecord
  has_many :forward_auth_rule_groups, dependent: :destroy
  has_many :allowed_groups, through: :forward_auth_rule_groups, source: :group

  validates :domain_pattern, presence: true, uniqueness: { case_sensitive: false }
  validates :active, inclusion: { in: [true, false] }

  normalizes :domain_pattern, with: ->(pattern) { pattern.strip.downcase }

  # Default header configuration
  DEFAULT_HEADERS = {
    user: 'X-Remote-User',
    email: 'X-Remote-Email',
    name: 'X-Remote-Name',
    groups: 'X-Remote-Groups',
    admin: 'X-Remote-Admin'
  }.freeze

  # Scopes
  scope :active, -> { where(active: true) }
  scope :ordered, -> { order(domain_pattern: :asc) }

  # Check if a domain matches this rule
  def matches_domain?(domain)
    return false if domain.blank?

    pattern = domain_pattern.gsub('.', '\.')
    pattern = pattern.gsub('*', '[^.]*')

    regex = Regexp.new("^#{pattern}$", Regexp::IGNORECASE)
    regex.match?(domain.downcase)
  end

  # Access control for forward auth
  def user_allowed?(user)
    return false unless active?
    return false unless user.active?

    # If no groups are specified, allow all active users (bypass)
    return true if allowed_groups.empty?

    # Otherwise, user must be in at least one of the allowed groups
    (user.groups & allowed_groups).any?
  end

  # Policy determination based on user status and rule configuration
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

  # Get effective header configuration (rule-specific + defaults)
  def effective_headers
    DEFAULT_HEADERS.merge((headers_config || {}).symbolize_keys)
  end

  # Generate headers for a specific user
  def headers_for_user(user)
    headers = {}
    effective = effective_headers

    # Only generate headers that are configured (not set to nil/false)
    effective.each do |key, header_name|
      next unless header_name.present?  # Skip disabled headers

      case key
      when :user, :email, :name
        headers[header_name] = user.email_address
      when :groups
        headers[header_name] = user.groups.pluck(:name).join(",") if user.groups.any?
      when :admin
        headers[header_name] = user.admin? ? "true" : "false"
      end
    end

    headers
  end

  # Check if all headers are disabled
  def headers_disabled?
    headers_config.present? && effective_headers.values.all?(&:blank?)
  end
end
