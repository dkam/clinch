class WebauthnCredential < ApplicationRecord
  belongs_to :user

  # Set default authenticator_type if not provided
  after_initialize :set_default_authenticator_type, if: :new_record?

  # Validations
  validates :external_id, presence: true, uniqueness: true
  validates :public_key, presence: true
  validates :sign_count, presence: true, numericality: {greater_than_or_equal_to: 0, only_integer: true}
  validates :nickname, presence: true
  validates :authenticator_type, inclusion: {in: %w[platform cross-platform]}

  # Scopes for querying
  scope :active, -> { where(nil) } # All credentials are active (we can add revoked_at later if needed)
  scope :platform_authenticators, -> { where(authenticator_type: "platform") }
  scope :roaming_authenticators, -> { where(authenticator_type: "cross-platform") }
  scope :recently_used, -> { where.not(last_used_at: nil).order(last_used_at: :desc) }
  scope :never_used, -> { where(last_used_at: nil) }

  # Update last used timestamp and sign count after successful authentication
  def update_usage!(sign_count:, ip_address: nil, user_agent: nil)
    update!(
      last_used_at: Time.current,
      last_used_ip: ip_address,
      sign_count: sign_count,
      user_agent: user_agent
    )
  end

  # Check if this is a platform authenticator (built-in device)
  def platform_authenticator?
    authenticator_type == "platform"
  end

  # Check if this is a roaming authenticator (USB/NFC/Bluetooth key)
  def roaming_authenticator?
    authenticator_type == "cross-platform"
  end

  # Check if this credential is backed up (synced passkeys)
  def backed_up?
    backup_eligible? && backup_state?
  end

  # Human readable description
  def description
    if nickname.present?
      "#{nickname} (#{authenticator_type.humanize})"
    else
      "#{authenticator_type.humanize} Authenticator"
    end
  end

  # Check if sign count is suspicious (clone detection)
  def suspicious_sign_count?(new_sign_count)
    return false if sign_count.zero? && new_sign_count > 0 # First use
    return false if new_sign_count > sign_count # Normal increment

    # Sign count didn't increase - possible clone
    true
  end

  # Format for display in UI
  def display_name
    nickname || "#{authenticator_type&.humanize} Authenticator"
  end

  # When was this credential created?
  def created_recently?
    created_at > 1.week.ago
  end

  # How long ago was this last used?
  def last_used_ago
    return "Never" unless last_used_at

    time_ago_in_words(last_used_at)
  end

  private

  def set_default_authenticator_type
    self.authenticator_type ||= "cross-platform"
  end

  def time_ago_in_words(time)
    seconds = Time.current - time
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24

    if days > 0
      "#{days.floor} day#{"s" if days > 1} ago"
    elsif hours > 0
      "#{hours.floor} hour#{"s" if hours > 1} ago"
    elsif minutes > 0
      "#{minutes.floor} minute#{"s" if minutes > 1} ago"
    else
      "Just now"
    end
  end
end
