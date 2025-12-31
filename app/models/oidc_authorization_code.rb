class OidcAuthorizationCode < ApplicationRecord
  belongs_to :application
  belongs_to :user

  attr_accessor :plaintext_code

  before_validation :generate_code, on: :create
  before_validation :set_expiry, on: :create

  validates :code_hmac, presence: true, uniqueness: true
  validates :redirect_uri, presence: true
  validates :code_challenge_method, inclusion: { in: %w[plain S256], allow_nil: true }
  validate :validate_code_challenge_format, if: -> { code_challenge.present? }

  scope :valid, -> { where(used: false).where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }

  # Find authorization code by plaintext code using HMAC verification
  def self.find_by_plaintext(plaintext_code)
    return nil if plaintext_code.blank?

    code_hmac = compute_code_hmac(plaintext_code)
    find_by(code_hmac: code_hmac)
  end

  # Compute HMAC for code lookup
  def self.compute_code_hmac(plaintext_code)
    OpenSSL::HMAC.hexdigest('SHA256', TokenHmac::KEY, plaintext_code)
  end

  def expired?
    expires_at <= Time.current
  end

  def usable?
    !used? && !expired?
  end

  def consume!
    update!(used: true)
  end

  def uses_pkce?
    code_challenge.present?
  end

  private

  def generate_code
    # Generate random plaintext code
    self.plaintext_code ||= SecureRandom.urlsafe_base64(32)
    # Store HMAC in database (not plaintext)
    self.code_hmac ||= self.class.compute_code_hmac(plaintext_code)
  end

  def set_expiry
    self.expires_at ||= 10.minutes.from_now
  end

  def validate_code_challenge_format
    # PKCE code challenge should be base64url-encoded, 43-128 characters
    unless code_challenge.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
      errors.add(:code_challenge, "must be 43-128 characters of base64url encoding")
    end
  end
end
