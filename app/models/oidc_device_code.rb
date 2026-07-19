# OAuth 2.0 Device Authorization Grant code (RFC 8628).
#
# Mirrors OidcAuthorizationCode: the long device_code is opaque and stored as an
# HMAC, while the short user_code is stored in plaintext because the user types it
# back on the verification page. A record is created "pending" by the device
# authorization endpoint, moved to "approved" (with a user) or "denied" on the
# verification page, and consumed by the token endpoint once approved.
class OidcDeviceCode < ApplicationRecord
  belongs_to :application
  belongs_to :user, optional: true # nil until the request is approved

  # Tokens minted from this code, so a replayed (already-redeemed) code can revoke
  # every token descended from it — mirrors OidcAuthorizationCode.
  has_many :oidc_access_tokens, dependent: :nullify
  has_many :oidc_refresh_tokens, dependent: :nullify

  # Alphabet for the user_code: uppercase letters + digits, minus visually
  # ambiguous characters (0/O, 1/I, etc.) so it is easy to read and type.
  USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars.freeze
  USER_CODE_GROUP_SIZE = 4
  USER_CODE_GROUPS = 2 # e.g. "WDJB-MJHT"

  STATUSES = %w[pending approved denied].freeze

  # Polling interval, in seconds. The token endpoint bumps the persisted interval
  # by INTERVAL_INCREMENT on each too-fast poll (RFC 8628 §3.5 slow_down), but
  # clamps it to MAX_INTERVAL so a client polling slightly fast — or an attacker
  # spamming a known device_code — can't balloon it past the expiry window and
  # starve a well-behaved client of its token.
  INTERVAL_INCREMENT = 5
  MAX_INTERVAL = 30

  attr_accessor :plaintext_device_code

  before_validation :generate_device_code, on: :create
  before_validation :generate_user_code, on: :create
  before_validation :set_expiry, on: :create

  validates :device_code_hmac, presence: true, uniqueness: true
  validates :user_code, presence: true, uniqueness: true
  validates :status, inclusion: {in: STATUSES}
  validates :code_challenge_method, inclusion: {in: %w[S256], allow_nil: true}
  validate :validate_code_challenge_format, if: -> { code_challenge.present? }

  scope :valid, -> { where(status: "pending").where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at <= ?", Time.current) }

  # Find a device code by its plaintext device_code using HMAC verification.
  def self.find_by_plaintext_device_code(plaintext_device_code)
    return nil if plaintext_device_code.blank?

    find_by(device_code_hmac: compute_device_code_hmac(plaintext_device_code))
  end

  # Look up a device code by the human-typed user_code. Normalizes case and
  # strips separators/whitespace so "wdjb-mjht" and "WDJB MJHT" both match.
  def self.find_by_user_code(user_code)
    return nil if user_code.blank?

    find_by(user_code: normalize_user_code(user_code))
  end

  def self.normalize_user_code(user_code)
    user_code.to_s.upcase.gsub(/[^A-Z0-9]/, "")
  end

  def self.compute_device_code_hmac(plaintext_device_code)
    OpenSSL::HMAC.hexdigest("SHA256", TokenHmac::KEY, plaintext_device_code)
  end

  def expired?
    expires_at <= Time.current
  end

  def pending?
    status == "pending"
  end

  def approved?
    status == "approved"
  end

  def denied?
    status == "denied"
  end

  def uses_pkce?
    code_challenge.present?
  end

  # True once the approved code has been exchanged for tokens. The row is kept
  # (not destroyed) so a replay is detectable and its tokens can be revoked.
  def redeemed?
    redeemed_at.present?
  end

  # Grant the request: attach the approving user and capture their auth context.
  def approve!(user:, acr:, auth_time:)
    update!(status: "approved", user: user, acr: acr, auth_time: auth_time)
  end

  def deny!
    update!(status: "denied")
  end

  private

  def generate_device_code
    self.plaintext_device_code ||= SecureRandom.urlsafe_base64(48)
    self.device_code_hmac ||= self.class.compute_device_code_hmac(plaintext_device_code)
  end

  # Number of fresh candidates to try before falling back to the DB unique index.
  USER_CODE_MAX_ATTEMPTS = 10

  def generate_user_code
    return if user_code.present?

    # Regenerate on the (astronomically rare) collision with an existing code so a
    # client never gets an error just because two codes happened to match. The DB
    # unique index remains the final guard against a concurrent-insert race.
    USER_CODE_MAX_ATTEMPTS.times do
      candidate = random_user_code
      unless self.class.exists?(user_code: candidate)
        self.user_code = candidate
        return
      end
    end
    self.user_code = random_user_code
  end

  def random_user_code
    # The user_code is a security credential (typing it + Approve grants tokens),
    # so draw from a CSPRNG rather than Ruby's global Mersenne Twister PRNG.
    USER_CODE_GROUPS.times.map do
      USER_CODE_GROUP_SIZE.times.map { USER_CODE_ALPHABET.sample(random: SecureRandom) }.join
    end.join
  end

  def set_expiry
    self.expires_at ||= 10.minutes.from_now
  end

  def validate_code_challenge_format
    # PKCE code challenge should be base64url-encoded, 43-128 characters.
    unless code_challenge.match?(/\A[A-Za-z0-9\-_]{43,128}\z/)
      errors.add(:code_challenge, "must be 43-128 characters of base64url encoding")
    end
  end
end
