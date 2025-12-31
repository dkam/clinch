class OidcRefreshToken < ApplicationRecord
  belongs_to :application
  belongs_to :user
  belongs_to :oidc_access_token

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create
  before_validation :set_token_family_id, on: :create

  validates :token_hmac, presence: true, uniqueness: true

  scope :valid, -> { where("expires_at > ?", Time.current).where(revoked_at: nil) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :active, -> { valid }

  # For token rotation detection (prevents reuse attacks)
  scope :in_family, ->(family_id) { where(token_family_id: family_id) }

  attr_accessor :token  # Store plaintext token temporarily for returning to client

  # Find refresh token by plaintext token using HMAC verification
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
  end

  # Revoke all refresh tokens in the same family (token rotation security)
  def revoke_family!
    return unless token_family_id.present?

    OidcRefreshToken.in_family(token_family_id).update_all(revoked_at: Time.current)
  end

  private

  def generate_token
    # Generate random plaintext token
    self.token ||= SecureRandom.urlsafe_base64(48)
    # Store HMAC in database (not plaintext)
    self.token_hmac ||= self.class.compute_token_hmac(token)
  end

  def set_expiry
    # Use application's configured refresh token TTL
    self.expires_at ||= application.refresh_token_expiry
  end

  def set_token_family_id
    # Use a random ID to group tokens in the same rotation chain
    # This helps detect token reuse attacks
    self.token_family_id ||= SecureRandom.random_number(2**31)
  end
end
