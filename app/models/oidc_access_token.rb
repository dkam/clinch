class OidcAccessToken < ApplicationRecord
  belongs_to :application
  belongs_to :user
  has_many :oidc_refresh_tokens, dependent: :destroy

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create

  validates :token, uniqueness: true, presence: true

  scope :valid, -> { where("expires_at > ?", Time.current).where(revoked_at: nil) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :active, -> { valid }

  attr_accessor :plaintext_token  # Store plaintext temporarily for returning to client

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

  # Check if a plaintext token matches the hashed token
  def token_matches?(plaintext_token)
    return false if plaintext_token.blank?

    # Use BCrypt to compare if token_digest exists
    if token_digest.present?
      BCrypt::Password.new(token_digest) == plaintext_token
    # Fall back to direct comparison for backward compatibility
    elsif token.present?
      token == plaintext_token
    else
      false
    end
  end

  # Find by token (validates and checks if revoked)
  def self.find_by_token(plaintext_token)
    return nil if plaintext_token.blank?

    # Find all non-revoked, non-expired tokens
    valid.find_each do |access_token|
      # Use BCrypt to compare (if token_digest exists) or direct comparison
      if access_token.token_digest.present?
        return access_token if BCrypt::Password.new(access_token.token_digest) == plaintext_token
      elsif access_token.token == plaintext_token
        return access_token
      end
    end
    nil
  end

  private

  def generate_token
    return if token.present?

    # Generate opaque access token
    plaintext = SecureRandom.urlsafe_base64(48)
    self.plaintext_token = plaintext  # Store temporarily for returning to client
    self.token_digest = BCrypt::Password.create(plaintext)
    # Keep token column for backward compatibility during migration
    self.token = plaintext
  end

  def set_expiry
    self.expires_at ||= application.access_token_expiry
  end
end
