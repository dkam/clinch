class OidcAccessToken < ApplicationRecord
  belongs_to :application
  belongs_to :user
  belongs_to :oidc_authorization_code, optional: true
  belongs_to :oidc_device_code, optional: true
  has_many :oidc_refresh_tokens, dependent: :destroy

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create

  validates :token_hmac, presence: true, uniqueness: true

  scope :valid, -> { where("expires_at > ?", Time.current).where(revoked_at: nil) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :active, -> { valid }

  attr_accessor :plaintext_token  # Store plaintext temporarily for returning to client

  # Resolve whatever the client actually presented — an opaque handle or an
  # RFC 9068 JWT (ADR 0007) — to its record. Every endpoint that accepts an
  # access token goes through here, so a client that opted into JWTs can still
  # introspect and revoke exactly like an opaque one.
  #
  # A JWT is verified (signature, typ, issuer, expiry) *before* its jti is used
  # for lookup, so an attacker cannot probe for records with a forged token.
  def self.find_by_presented_token(presented)
    return nil if presented.blank?
    return find_by_token(presented) unless presented.count(".") == 2

    payload = OidcJwtService.decode_access_token(presented) or return nil
    find_by(token_hmac: payload["jti"])
  end

  # Find access token by plaintext token using HMAC verification
  def self.find_by_token(plaintext_token)
    return nil if plaintext_token.blank?

    token_hmac = compute_token_hmac(plaintext_token)
    find_by(token_hmac: token_hmac)
  end

  # Compute HMAC for token lookup
  def self.compute_token_hmac(plaintext_token)
    OpenSSL::HMAC.hexdigest("SHA256", TokenHmac::KEY, plaintext_token)
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

  # What actually goes over the wire as `access_token` in the token response:
  # the opaque handle, or an RFC 9068 JWT when the client opted into that
  # format (ADR 0007). Only meaningful on a freshly created record, since the
  # opaque plaintext exists nowhere but in memory.
  def wire_value(consent: nil)
    return plaintext_token unless application.jwt_access_tokens?

    OidcJwtService.generate_access_token(self, consent: consent)
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
