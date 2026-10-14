class Group < ApplicationRecord
  has_many :user_groups, dependent: :destroy
  has_many :users, through: :user_groups
  has_many :application_groups, dependent: :destroy
  has_many :applications, through: :application_groups

  validates :name, presence: true, uniqueness: {case_sensitive: false}
  normalizes :name, with: ->(name) { name.strip.downcase }
  validate :no_reserved_claim_names

  scope :auto_assign, -> { where(auto_assign: true) }
  scope :admin, -> { where(admin: true) }

  before_destroy :ensure_other_admin_group_exists

  # Parse custom_claims JSON field
  def parsed_custom_claims
    return {} if custom_claims.blank?
    custom_claims.is_a?(Hash) ? custom_claims : {}
  end

  private

  def ensure_other_admin_group_exists
    return unless admin?
    return if Group.where(admin: true).where.not(id: id).exists?
    errors.add(:base, "cannot delete the last administrators group")
    throw :abort
  end

  def no_reserved_claim_names
    return if custom_claims.blank?

    reserved_used = parsed_custom_claims.keys.map(&:to_s) & OidcClaims::RESERVED
    if reserved_used.any?
      errors.add(:custom_claims, "cannot override reserved OIDC claims: #{reserved_used.join(", ")}")
    end
  end
end
