class OidcAuthorizationCode < ApplicationRecord
  belongs_to :application
  belongs_to :user

  before_validation :generate_code, on: :create
  before_validation :set_expiry, on: :create

  validates :code, presence: true, uniqueness: true
  validates :redirect_uri, presence: true

  scope :valid, -> { where(used: false).where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }

  def expired?
    expires_at <= Time.current
  end

  def usable?
    !used? && !expired?
  end

  def consume!
    update!(used: true)
  end

  private

  def generate_code
    self.code ||= SecureRandom.urlsafe_base64(32)
  end

  def set_expiry
    self.expires_at ||= 10.minutes.from_now
  end
end
