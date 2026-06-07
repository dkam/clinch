class Application < ApplicationRecord
  has_secure_password :client_secret, validations: false

  # Virtual attribute to control client type during creation
  # When true, no client_secret will be generated (public client)
  attr_accessor :is_public_client

  # Virtual setters for TTL fields - accept human-friendly durations
  # e.g., "1h", "30m", "1d", or plain numbers "3600"
  def access_token_ttl=(value)
    parsed = DurationParser.parse(value)
    super(parsed)
  end

  def refresh_token_ttl=(value)
    parsed = DurationParser.parse(value)
    super(parsed)
  end

  def id_token_ttl=(value)
    parsed = DurationParser.parse(value)
    super(parsed)
  end

  after_commit :bust_forward_auth_cache, if: :forward_auth?

  has_one_attached :icon
  has_one_attached :icon_dark

  ICON_ATTACHMENTS = %i[icon icon_dark].freeze

  before_validation :sanitize_svg_icons
  after_save :fix_icon_content_types

  has_many :application_groups, dependent: :destroy
  has_many :allowed_groups, through: :application_groups, source: :group
  has_many :application_user_claims, dependent: :destroy
  has_many :oidc_authorization_codes, dependent: :destroy
  has_many :oidc_access_tokens, dependent: :destroy
  has_many :oidc_refresh_tokens, dependent: :destroy
  has_many :oidc_user_consents, dependent: :destroy
  has_many :api_keys, dependent: :destroy

  validates :name, presence: true
  validates :slug, presence: true, uniqueness: {case_sensitive: false},
    format: {with: /\A[a-z0-9-]+\z/, message: "only lowercase letters, numbers, and hyphens"}
  validates :app_type, presence: true,
    inclusion: {in: %w[oidc forward_auth]}
  validates :client_id, uniqueness: {allow_nil: true}
  validates :client_secret, presence: true, on: :create, if: -> { oidc? && confidential_client? }
  validates :domain_pattern, presence: true, uniqueness: {case_sensitive: false}, if: :forward_auth?
  validates :landing_url, format: {with: URI::RFC2396_PARSER.make_regexp(%w[http https]), allow_nil: true, message: "must be a valid URL"}
  validates :backchannel_logout_uri, format: {
    with: URI::RFC2396_PARSER.make_regexp(%w[http https]),
    allow_nil: true,
    message: "must be a valid HTTP or HTTPS URL"
  }
  validate :backchannel_logout_uri_must_be_https_in_production, if: -> { backchannel_logout_uri.present? }

  # Icon validation using ActiveStorage validators
  validate :icon_validation

  # Token TTL validations (for OIDC apps)
  validates :access_token_ttl, numericality: {greater_than_or_equal_to: 300, less_than_or_equal_to: 86400}, if: :oidc?  # 5 min - 24 hours
  validates :refresh_token_ttl, numericality: {greater_than_or_equal_to: 300, less_than_or_equal_to: 7776000}, if: :oidc?  # 5 min - 90 days
  validates :id_token_ttl, numericality: {greater_than_or_equal_to: 300, less_than_or_equal_to: 86400}, if: :oidc?  # 5 min - 24 hours

  normalizes :slug, with: ->(slug) { slug.strip.downcase }
  normalizes :domain_pattern, with: ->(pattern) {
    normalized = pattern&.strip&.downcase
    normalized.blank? ? nil : normalized
  }
  normalizes :backchannel_logout_uri, with: ->(uri) {
    normalized = uri&.strip
    normalized.blank? ? nil : normalized
  }

  before_validation :generate_client_credentials, on: :create, if: :oidc?

  # Default header configuration for ForwardAuth
  DEFAULT_HEADERS = {
    user: "X-Remote-User",
    email: "X-Remote-Email",
    name: "X-Remote-Name",
    username: "X-Remote-Username",
    groups: "X-Remote-Groups",
    admin: "X-Remote-Admin"
  }.freeze

  # Scopes
  scope :active, -> { where(active: true) }
  scope :oidc, -> { where(app_type: "oidc") }
  scope :forward_auth, -> { where(app_type: "forward_auth") }
  scope :ordered, -> { order(domain_pattern: :asc) }

  # Type checks
  def oidc?
    app_type == "oidc"
  end

  def forward_auth?
    app_type == "forward_auth"
  end

  # Client type checks (for OIDC)
  def public_client?
    client_secret_digest.blank?
  end

  def confidential_client?
    !public_client?
  end

  # PKCE requirement check
  # Public clients MUST use PKCE (no client secret to protect auth code)
  # Confidential clients can optionally require PKCE (OAuth 2.1 recommendation)
  def requires_pkce?
    return false unless oidc?
    return true if public_client?  # Always require PKCE for public clients
    require_pkce?  # Check the flag for confidential clients
  end

  # Access control
  # Default-deny: an empty allowed_groups list means no one gets in.
  # To make an app accessible to "everyone", attach the seeded auto-assign
  # group (or any group every user is in).
  def user_allowed?(user)
    return false unless active?
    return false unless user.active?
    (user.groups & allowed_groups).any?
  end

  # OIDC helpers
  def parsed_redirect_uris
    return [] unless redirect_uris.present?
    JSON.parse(redirect_uris)
  rescue JSON::ParserError
    redirect_uris.split("\n").map(&:strip).reject(&:blank?)
  end

  def parsed_metadata
    return {} unless metadata.present?
    JSON.parse(metadata)
  rescue JSON::ParserError
    {}
  end

  # ForwardAuth helpers
  def parsed_headers_config
    return {} unless headers_config.present?
    headers_config.is_a?(Hash) ? headers_config : JSON.parse(headers_config)
  rescue JSON::ParserError
    {}
  end

  # Check if a domain matches this application's pattern (for ForwardAuth)
  def matches_domain?(domain)
    return false if domain.blank? || !forward_auth?

    pattern = domain_pattern.gsub(".", '\.')
    pattern = pattern.gsub("*", "[^.]*")

    regex = Regexp.new("^#{pattern}$", Regexp::IGNORECASE)
    regex.match?(domain.downcase)
  end

  # Policy determination based on user status (for ForwardAuth)
  def policy_for_user(user)
    return "deny" unless active?
    return "deny" unless user.active?

    if user_allowed?(user)
      # Require 2FA if user has TOTP configured, otherwise one factor
      user.totp_enabled? ? "two_factor" : "one_factor"
    else
      "deny"
    end
  end

  # Get effective header configuration (for ForwardAuth)
  def effective_headers
    DEFAULT_HEADERS.merge(parsed_headers_config.symbolize_keys)
  end

  # Generate headers for a specific user (for ForwardAuth)
  def headers_for_user(user)
    headers = {}
    effective = effective_headers

    # Only generate headers that are configured (not set to nil/false)
    effective.each do |key, header_name|
      next unless header_name.present?  # Skip disabled headers

      case key
      when :user, :email
        headers[header_name] = user.email_address
      when :name
        headers[header_name] = user.name.presence || user.email_address
      when :username
        headers[header_name] = user.username if user.username.present?
      when :groups
        headers[header_name] = user.groups.map(&:name).join(",") if user.groups.any?
      when :admin
        headers[header_name] = user.admin? ? "true" : "false"
      end
    end

    headers
  end

  # Check if all headers are disabled (for ForwardAuth)
  def headers_disabled?
    headers_config.present? && effective_headers.values.all?(&:blank?)
  end

  # Generate and return a new client secret
  def generate_new_client_secret!
    secret = SecureRandom.urlsafe_base64(48)
    self.client_secret = secret
    save!
    secret
  end

  # Token TTL helper methods (for OIDC)
  def access_token_expiry
    (access_token_ttl || 3600).seconds.from_now
  end

  def refresh_token_expiry
    (refresh_token_ttl || 2592000).seconds.from_now
  end

  def id_token_expiry_seconds
    id_token_ttl || 3600
  end

  # Human-readable TTL for display
  def access_token_ttl_human
    duration_to_human(access_token_ttl || 3600)
  end

  def refresh_token_ttl_human
    duration_to_human(refresh_token_ttl || 2592000)
  end

  def id_token_ttl_human
    duration_to_human(id_token_ttl || 3600)
  end

  # Get app-specific custom claims for a user
  def custom_claims_for_user(user)
    app_claim = application_user_claims.find_by(user: user)
    app_claim&.parsed_custom_claims || {}
  end

  # Check if this application supports backchannel logout
  def supports_backchannel_logout?
    backchannel_logout_uri.present?
  end

  # Check if a user has an active session with this application
  # (i.e., has valid, non-revoked tokens)
  def user_has_active_session?(user)
    oidc_access_tokens.where(user: user).valid.exists? ||
      oidc_refresh_tokens.where(user: user).valid.exists?
  end

  private

  def bust_forward_auth_cache
    Rails.application.config.forward_auth_cache&.delete("fa_apps")
  end

  def fix_icon_content_types
    ICON_ATTACHMENTS.each do |attr|
      attachment = public_send(attr)
      next unless attachment.attached?
      # Fix SVG content type if it was detected incorrectly
      if attachment.filename.extension == "svg" && attachment.content_type == "application/octet-stream"
        attachment.blob.update(content_type: "image/svg+xml")
      end
    end
  end

  def sanitize_svg_icons
    # Runs in before_validation. The blob has NOT yet been uploaded to disk at
    # this point (Active Storage uploads in before_save), so we cannot call
    # download — we must read from the pending attachable.
    #
    # attach below re-sets attachment_changes and would re-fire this callback;
    # we skip if the pending attachable is the cleaned hash we just installed
    # (tracked by object identity, per-attribute).
    @svg_sanitized_attachables ||= {}

    ICON_ATTACHMENTS.each do |attr|
      change = attachment_changes[attr.to_s]
      next unless change
      attachable = change.attachable
      next if attachable.equal?(@svg_sanitized_attachables[attr])

      raw_svg, filename, content_type = read_pending_icon(attachable)
      next unless raw_svg
      next unless content_type == "image/svg+xml" || filename.to_s.downcase.end_with?(".svg")

      doc = Loofah.xml_document(raw_svg)
      doc.scrub!(SvgScrubber.new)
      clean_svg = doc.to_xml

      sanitized = {
        io: StringIO.new(clean_svg),
        filename: filename,
        content_type: "image/svg+xml"
      }
      @svg_sanitized_attachables[attr] = sanitized
      public_send(attr).attach(sanitized)
    end
  end

  def read_pending_icon(attachable)
    case attachable
    when ActionDispatch::Http::UploadedFile, Rack::Test::UploadedFile
      content = attachable.read
      attachable.rewind
      [content, attachable.original_filename, attachable.content_type]
    when Hash
      io = attachable[:io] || attachable["io"]
      return [nil, nil, nil] unless io
      content = io.read
      io.rewind if io.respond_to?(:rewind)
      [content,
        attachable[:filename] || attachable["filename"],
        attachable[:content_type] || attachable["content_type"]]
    else
      [nil, nil, nil]
    end
  end

  def icon_validation
    allowed_types = ["image/png", "image/jpg", "image/jpeg", "image/gif", "image/svg+xml"]

    ICON_ATTACHMENTS.each do |attr|
      attachment = public_send(attr)
      next unless attachment.attached?

      unless allowed_types.include?(attachment.content_type)
        errors.add(attr, "must be a PNG, JPG, GIF, or SVG image")
      end

      if attachment.blob.byte_size > 2.megabytes
        errors.add(attr, "must be less than 2MB")
      end
    end
  end

  def duration_to_human(seconds)
    if seconds < 3600
      "#{seconds / 60} minutes"
    elsif seconds < 86400
      "#{seconds / 3600} hours"
    else
      "#{seconds / 86400} days"
    end
  end

  def generate_client_credentials
    self.client_id ||= SecureRandom.urlsafe_base64(32)
    # Generate client secret only for confidential clients
    # Public clients (is_public_client checked) don't get a secret - they use PKCE only
    if new_record? && client_secret.blank? && !is_public_client_selected?
      secret = SecureRandom.urlsafe_base64(48)
      self.client_secret = secret
    end
  end

  # Check if the user selected public client option
  def is_public_client_selected?
    ActiveModel::Type::Boolean.new.cast(is_public_client)
  end

  def backchannel_logout_uri_must_be_https_in_production
    return unless Rails.env.production?
    return unless backchannel_logout_uri.present?

    begin
      uri = URI.parse(backchannel_logout_uri)
      unless uri.scheme == "https"
        errors.add(:backchannel_logout_uri, "must use HTTPS in production")
      end
    rescue URI::InvalidURIError
      # Let the format validator handle invalid URIs
    end
  end
end
