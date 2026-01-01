class Group < ApplicationRecord
  has_many :user_groups, dependent: :destroy
  has_many :users, through: :user_groups
  has_many :application_groups, dependent: :destroy
  has_many :applications, through: :application_groups

  # Reserved OIDC claim names that should not be overridden
  RESERVED_CLAIMS = %w[
    iss sub aud exp iat nbf jti nonce azp
    email email_verified preferred_username name
    groups
  ].freeze

  validates :name, presence: true, uniqueness: {case_sensitive: false}
  normalizes :name, with: ->(name) { name.strip.downcase }
  validate :no_reserved_claim_names

  # Parse custom_claims JSON field
  def parsed_custom_claims
    return {} if custom_claims.blank?
    custom_claims.is_a?(Hash) ? custom_claims : {}
  end

  private

  def no_reserved_claim_names
    return if custom_claims.blank?

    reserved_used = parsed_custom_claims.keys.map(&:to_s) & RESERVED_CLAIMS
    if reserved_used.any?
      errors.add(:custom_claims, "cannot override reserved OIDC claims: #{reserved_used.join(", ")}")
    end
  end
end
