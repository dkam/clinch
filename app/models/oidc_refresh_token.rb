class OidcRefreshToken < ApplicationRecord
  belongs_to :application
  belongs_to :user
  belongs_to :oidc_access_token
  has_many :oidc_access_tokens, foreign_key: :oidc_access_token_id, dependent: :nullify

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create
  before_validation :set_token_family_id, on: :create

  validates :token_digest, presence: true, uniqueness: true

  scope :valid, -> { where("expires_at > ?", Time.current).where(revoked_at: nil) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :active, -> { valid }

  # For token rotation detection (prevents reuse attacks)
  scope :in_family, ->(family_id) { where(token_family_id: family_id) }

  attr_accessor :token  # Store plaintext token temporarily for returning to client

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

  # Verify a plaintext token against the stored digest
  def self.find_by_token(plaintext_token)
    return nil if plaintext_token.blank?

    # Try to find tokens that could match (we can't search by hash directly)
    # This is less efficient but necessary with BCrypt
    # In production, you might want to add a token prefix or other optimization
    all.find do |refresh_token|
      refresh_token.token_matches?(plaintext_token)
    end
  end

  def token_matches?(plaintext_token)
    return false if plaintext_token.blank? || token_digest.blank?

    BCrypt::Password.new(token_digest) == plaintext_token
  rescue BCrypt::Errors::InvalidHash
    false
  end

  private

  def generate_token
    # Generate a secure random token
    plaintext = SecureRandom.urlsafe_base64(48)
    self.token = plaintext  # Store temporarily for returning to client

    # Hash it with BCrypt for storage
    self.token_digest = BCrypt::Password.create(plaintext)
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
