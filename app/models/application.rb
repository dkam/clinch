class Application < ApplicationRecord
  has_many :application_groups, dependent: :destroy
  has_many :allowed_groups, through: :application_groups, source: :group
  has_many :oidc_authorization_codes, dependent: :destroy
  has_many :oidc_access_tokens, dependent: :destroy

  validates :name, presence: true
  validates :slug, presence: true, uniqueness: { case_sensitive: false },
                  format: { with: /\A[a-z0-9\-]+\z/, message: "only lowercase letters, numbers, and hyphens" }
  validates :app_type, presence: true,
                      inclusion: { in: %w[oidc saml] }
  validates :client_id, uniqueness: { allow_nil: true }

  normalizes :slug, with: ->(slug) { slug.strip.downcase }

  before_validation :generate_client_credentials, on: :create, if: :oidc?

  # Scopes
  scope :active, -> { where(active: true) }
  scope :oidc, -> { where(app_type: "oidc") }
  scope :saml, -> { where(app_type: "saml") }

  # Type checks
  def oidc?
    app_type == "oidc"
  end

  def saml?
    app_type == "saml"
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

  private

  def generate_client_credentials
    self.client_id ||= SecureRandom.urlsafe_base64(32)
    self.client_secret ||= SecureRandom.urlsafe_base64(48)
  end
end
