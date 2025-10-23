class OidcAccessToken < ApplicationRecord
  belongs_to :application
  belongs_to :user

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create

  validates :token, presence: true, uniqueness: true

  scope :valid, -> { where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }

  def expired?
    expires_at <= Time.current
  end

  def active?
    !expired?
  end

  def revoke!
    update!(expires_at: Time.current)
  end

  private

  def generate_token
    self.token ||= SecureRandom.urlsafe_base64(48)
  end

  def set_expiry
    self.expires_at ||= 1.hour.from_now
  end
end
