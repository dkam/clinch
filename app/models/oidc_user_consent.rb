class OidcUserConsent < ApplicationRecord
  belongs_to :user
  belongs_to :application

  validates :user, :application, :scopes_granted, :granted_at, presence: true
  validates :user_id, uniqueness: { scope: :application_id }

  before_validation :set_granted_at, on: :create
  before_validation :set_sid, on: :create

  # Parse scopes_granted into an array
  def scopes
    scopes_granted.split(' ')
  end

  # Set scopes from an array
  def scopes=(scope_array)
    self.scopes_granted = Array(scope_array).uniq.join(' ')
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
      when 'openid'
        'Basic authentication'
      when 'profile'
        'Profile information'
      when 'email'
        'Email address'
      when 'groups'
        'Group membership'
      else
        scope.humanize
      end
    end.join(', ')
  end

  # Find consent by SID
  def self.find_by_sid(sid)
    find_by(sid: sid)
  end

  private

  def set_granted_at
    self.granted_at ||= Time.current
  end

  def set_sid
    self.sid ||= SecureRandom.uuid
  end
end
