class OidcUserConsent < ApplicationRecord
  belongs_to :user
  belongs_to :application

  validates :user, :application, :scopes_granted, :granted_at, presence: true
  validates :user_id, uniqueness: {scope: :application_id}

  before_validation :set_granted_at, on: :create
  before_validation :set_sid, on: :create

  # Withdrawing consent has to cut off what it authorised — every path that
  # deletes a consent (one app, all apps, account cleanup) goes through here.
  # The subject is pinned first so the next consent keeps it (CLN-05).
  before_destroy :pin_subject, :revoke_tokens

  # Upsert a user's consent for an application. The record is unique on
  # user+application and shared across the browser and device flows.
  #
  # merge: false (the browser consent screen) records exactly the scopes the user
  # just approved. merge: true (device approval) unions the scopes into any
  # existing grant and leaves stored claims untouched, so a narrower device
  # request can never shrink a prior grant or wipe its claims. claims_requests is
  # written only when supplied (nil = keep whatever is stored, defaulting to {}
  # for a brand-new record).
  def self.record!(user:, application:, scopes:, claims_requests: nil, merge: false)
    consent = find_or_initialize_by(user: user, application: application)
    incoming = Array(scopes)
    consent.scopes = merge ? (consent.scopes | incoming) : incoming
    consent.claims_requests = claims_requests unless claims_requests.nil?
    consent.claims_requests ||= {}
    consent.granted_at = Time.current
    consent.save!
    consent
  end

  # Parse scopes_granted into an array (nil-safe for not-yet-saved records).
  def scopes
    scopes_granted.to_s.split(" ")
  end

  # Set scopes from an array
  def scopes=(scope_array)
    self.scopes_granted = Array(scope_array).uniq.join(" ")
  end

  # Check if this consent covers the requested scopes
  def covers_scopes?(requested_scopes)
    requested = Array(requested_scopes).map(&:to_s)
    granted = scopes

    # All requested scopes must be included in granted scopes
    (requested - granted).empty?
  end

  # Get a human-readable list of scopes
  def formatted_scopes
    scopes.map do |scope|
      case scope
      when "openid"
        "Basic authentication"
      when "profile"
        "Profile information"
      when "email"
        "Email address"
      when "groups"
        "Group membership"
      else
        scope.humanize
      end
    end.join(", ")
  end

  # The `sub` this user has at this application. Not the sid: the sid names this
  # consent (backchannel logout), the subject outlives it.
  def subject
    OidcPairwiseSubject.for(user, application)
  end

  # Find consent by SID
  def self.find_by_sid(sid)
    find_by(sid: sid)
  end

  # Parse claims_requests JSON field
  def parsed_claims_requests
    return {} if claims_requests.blank?
    claims_requests.is_a?(Hash) ? claims_requests : {}
  end

  private

  def set_granted_at
    self.granted_at ||= Time.current
  end

  def set_sid
    self.sid ||= SecureRandom.uuid
  end

  def pin_subject
    subject
  end

  def revoke_tokens
    now = Time.current
    OidcAccessToken.where(user_id: user_id, application_id: application_id, revoked_at: nil).update_all(revoked_at: now)
    OidcRefreshToken.where(user_id: user_id, application_id: application_id, revoked_at: nil).update_all(revoked_at: now)
  end
end
