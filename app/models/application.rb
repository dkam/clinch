class Application < ApplicationRecord
  has_secure_password :client_secret

  has_many :application_groups, dependent: :destroy
  has_many :allowed_groups, through: :application_groups, source: :group
  has_many :oidc_authorization_codes, dependent: :destroy
  has_many :oidc_access_tokens, dependent: :destroy
  has_many :application_roles, dependent: :destroy
  has_many :user_role_assignments, through: :application_roles

  validates :name, presence: true
  validates :slug, presence: true, uniqueness: { case_sensitive: false },
                  format: { with: /\A[a-z0-9\-]+\z/, message: "only lowercase letters, numbers, and hyphens" }
  validates :app_type, presence: true,
                      inclusion: { in: %w[oidc saml] }
  validates :client_id, uniqueness: { allow_nil: true }
  validates :role_mapping_mode, inclusion: { in: %w[disabled oidc_managed hybrid] }, allow_blank: true

  normalizes :slug, with: ->(slug) { slug.strip.downcase }

  before_validation :generate_client_credentials, on: :create, if: :oidc?

  # Scopes
  scope :active, -> { where(active: true) }
  scope :oidc, -> { where(app_type: "oidc") }
  scope :saml, -> { where(app_type: "saml") }
  scope :oidc_managed_roles, -> { where(role_mapping_mode: "oidc_managed") }
  scope :hybrid_roles, -> { where(role_mapping_mode: "hybrid") }

  # Type checks
  def oidc?
    app_type == "oidc"
  end

  def saml?
    app_type == "saml"
  end

  # Role mapping checks
  def role_mapping_enabled?
    role_mapping_mode.in?(['oidc_managed', 'hybrid'])
  end

  def oidc_managed_roles?
    role_mapping_mode == 'oidc_managed'
  end

  def hybrid_roles?
    role_mapping_mode == 'hybrid'
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

  def parsed_managed_permissions
    return {} unless managed_permissions.present?
    managed_permissions.is_a?(Hash) ? managed_permissions : JSON.parse(managed_permissions)
  rescue JSON::ParserError
    {}
  end

  # Role management methods
  def user_roles(user)
    application_roles.joins(:user_role_assignments)
                    .where(user_role_assignments: { user: user })
                    .active
  end

  def user_has_role?(user, role_name)
    user_roles(user).exists?(name: role_name)
  end

  def assign_role_to_user!(user, role_name, source: 'manual', metadata: {})
    role = application_roles.active.find_by!(name: role_name)
    role.assign_to_user!(user, source: source, metadata: metadata)
  end

  def remove_role_from_user!(user, role_name)
    role = application_roles.find_by!(name: role_name)
    role.remove_from_user!(user)
  end

  # Enhanced access control with roles
  def user_allowed_with_roles?(user)
    return user_allowed?(user) unless role_mapping_enabled?

    # For OIDC managed roles, check if user has any roles assigned
    if oidc_managed_roles?
      return user_roles(user).exists?
    end

    # For hybrid mode, either group-based access or role-based access works
    if hybrid_roles?
      return user_allowed?(user) || user_roles(user).exists?
    end

    user_allowed?(user)
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
