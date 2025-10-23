class ForwardAuthRule < ApplicationRecord
  has_many :forward_auth_rule_groups, dependent: :destroy
  has_many :allowed_groups, through: :forward_auth_rule_groups, source: :group

  validates :domain_pattern, presence: true, uniqueness: { case_sensitive: false }
  validates :active, inclusion: { in: [true, false] }

  normalizes :domain_pattern, with: ->(pattern) { pattern.strip.downcase }

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
end
