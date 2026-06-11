class Session < ApplicationRecord
  belongs_to :user

  before_create :set_expiry
  before_save :update_activity

  # Scopes
  scope :active, -> { where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  # Sessions whose owning user is currently active. Used at request time so a
  # disabled account cannot continue to authenticate with an existing session.
  scope :for_active_user, -> { joins(:user).where(users: {status: User.statuses[:active]}) }

  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  def active?
    !expired?
  end

  def touch_activity!
    update_column(:last_activity_at, Time.current)
  end

  private

  def set_expiry
    self.expires_at ||= remember_me ? 30.days.from_now : 24.hours.from_now
    self.last_activity_at ||= Time.current
  end

  def update_activity
    self.last_activity_at = Time.current if expires_at_changed? || new_record?
  end
end
