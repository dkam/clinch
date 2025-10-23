class Session < ApplicationRecord
  belongs_to :user

  before_create :set_expiry
  before_save :update_activity

  # Scopes
  scope :active, -> { where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }

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
