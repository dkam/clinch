class OidcAccessToken < ApplicationRecord
  belongs_to :application
  belongs_to :user
  has_many :oidc_refresh_tokens, dependent: :destroy

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create

  validates :token_hmac, presence: true, uniqueness: true

  scope :valid, -> { where("expires_at > ?", Time.current).where(revoked_at: nil) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :active, -> { valid }

  attr_accessor :plaintext_token  # Store plaintext temporarily for returning to client

  # Find access token by plaintext token using HMAC verification
  def self.find_by_token(plaintext_token)
    return nil if plaintext_token.blank?

    token_hmac = compute_token_hmac(plaintext_token)
    find_by(token_hmac: token_hmac)
  end

  # Compute HMAC for token lookup
  def self.compute_token_hmac(plaintext_token)
    OpenSSL::HMAC.hexdigest('SHA256', TokenHmac::KEY, plaintext_token)
  end

  def expired?
    expires_at <= Time.current
  end

  def revoked?
    revoked_at.present?
  end

  def active?
    !expired? && !revoked?
  end

  def revoke!
    update!(revoked_at: Time.current)
    # Also revoke associated refresh tokens
    oidc_refresh_tokens.each(&:revoke!)
  end

  private

  def generate_token
    # Generate random plaintext token
    self.plaintext_token ||= SecureRandom.urlsafe_base64(48)
    # Store HMAC in database (not plaintext)
    self.token_hmac ||= self.class.compute_token_hmac(plaintext_token)
  end

  def set_expiry
    self.expires_at ||= application.access_token_expiry
  end
end
