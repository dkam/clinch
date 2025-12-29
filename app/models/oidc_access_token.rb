class OidcAccessToken < ApplicationRecord
  include TokenPrefixable

  belongs_to :application
  belongs_to :user
  has_many :oidc_refresh_tokens, dependent: :destroy

  before_validation :generate_token_with_prefix, on: :create
  before_validation :set_expiry, on: :create

  validates :token_digest, presence: true
  validates :token_prefix, presence: true

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

  # find_by_token, token_matches?, and generate_token_with_prefix
  # are now provided by TokenPrefixable concern

  private

  def set_expiry
    self.expires_at ||= application.access_token_expiry
  end
end
