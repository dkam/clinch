class ApiKey < ApplicationRecord
  belongs_to :user
  belongs_to :application

  before_validation :generate_token, on: :create

  validates :name, presence: true
  validates :token_hmac, presence: true, uniqueness: true
  validate :application_must_be_forward_auth
  validate :user_must_have_access

  scope :active, -> { where(revoked_at: nil).where("expires_at IS NULL OR expires_at > ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }

  attr_accessor :plaintext_token

  def self.find_by_token(plaintext_token)
    return nil if plaintext_token.blank?

    token_hmac = compute_token_hmac(plaintext_token)
    find_by(token_hmac: token_hmac)
  end

  def self.compute_token_hmac(plaintext_token)
    OpenSSL::HMAC.hexdigest("SHA256", TokenHmac::KEY, plaintext_token)
  end

  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  def revoked?
    revoked_at.present?
  end

  def active?
    !expired? && !revoked?
  end

  def revoke!
    update!(revoked_at: Time.current)
  end

  def touch_last_used!
    update_column(:last_used_at, Time.current)
  end

  private

  def generate_token
    self.plaintext_token ||= "clk_#{SecureRandom.urlsafe_base64(48)}"
    self.token_hmac ||= self.class.compute_token_hmac(plaintext_token)
  end

  def application_must_be_forward_auth
    if application && !application.forward_auth?
      errors.add(:application, "must be a forward auth application")
    end
  end

  def user_must_have_access
    if user && application && !application.user_allowed?(user)
      errors.add(:user, "does not have access to this application")
    end
  end
end
