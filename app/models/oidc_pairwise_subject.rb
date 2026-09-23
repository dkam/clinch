# The `sub` a client sees for a user (CLN-05). It is the contract with the
# relying party: the same person must stay the same subject to that client for
# as long as the account exists. It used to live on the consent row, so
# revoking consent destroyed it and re-consenting minted a new one; it now
# outlives consent and goes only with the user or the application.
class OidcPairwiseSubject < ApplicationRecord
  belongs_to :user
  belongs_to :application

  # Seeded from the consent's sid when there is one, because that is the
  # subject this client has been given so far.
  def self.for(user, application)
    existing = find_by(user: user, application: application)
    return existing.subject if existing

    seed = OidcUserConsent.where(user: user, application: application).pick(:sid)
    create!(user: user, application: application, subject: seed || SecureRandom.uuid).subject
  rescue ActiveRecord::RecordNotUnique
    find_by!(user: user, application: application).subject
  end
end
