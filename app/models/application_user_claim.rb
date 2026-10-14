class ApplicationUserClaim < ApplicationRecord
  belongs_to :application
  belongs_to :user

  validates :user_id, uniqueness: {scope: :application_id}
  validate :no_reserved_claim_names

  # Parse custom_claims JSON field
  def parsed_custom_claims
    return {} if custom_claims.blank?
    custom_claims.is_a?(Hash) ? custom_claims : {}
  end

  private

  def no_reserved_claim_names
    return if custom_claims.blank?

    reserved_used = parsed_custom_claims.keys.map(&:to_s) & OidcClaims::RESERVED
    if reserved_used.any?
      errors.add(:custom_claims, "cannot override reserved OIDC claims: #{reserved_used.join(", ")}")
    end
  end
end
