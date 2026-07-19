require "uri"

# OAuth 2.0 Dynamic Client Registration (RFC 7591).
#
# Lets a client (e.g. an MCP connector such as Claude) register itself instead of
# being hand-created in the admin UI. Gated by a runtime toggle
# (Application.dynamic_registration_enabled?) that defaults off. Registered
# clients are default-deny — they have no allowed_groups until an admin attaches
# one — so an anonymous registration cannot reach any user's data on its own.
class OidcRegistrationController < ApplicationController
  allow_unauthenticated_access only: [:create]
  skip_before_action :verify_authenticity_token, only: [:create]

  rate_limit to: 10, within: 1.minute, only: [:create], with: -> {
    render json: {error: "too_many_requests", error_description: "Rate limit exceeded. Try again later."}, status: :too_many_requests
  }

  AUTH_METHODS = %w[none client_secret_basic client_secret_post].freeze
  SUPPORTED_GRANT_TYPES = %w[authorization_code refresh_token].freeze
  SUPPORTED_RESPONSE_TYPES = %w[code].freeze

  # POST /oauth/register
  def create
    unless Application.dynamic_registration_enabled?
      render json: {error: "access_denied", error_description: "Dynamic client registration is disabled"}, status: :forbidden
      return
    end

    metadata = parse_body
    if metadata == :invalid
      return register_error("invalid_client_metadata", "Request body must be a valid JSON object")
    end

    auth_method = metadata["token_endpoint_auth_method"].presence || "client_secret_basic"
    unless AUTH_METHODS.include?(auth_method)
      return register_error("invalid_client_metadata", "Unsupported token_endpoint_auth_method")
    end

    grant_types = Array(metadata["grant_types"].presence || ["authorization_code"])
    if (grant_types - SUPPORTED_GRANT_TYPES).any?
      return register_error("invalid_client_metadata", "Unsupported grant_types; only #{SUPPORTED_GRANT_TYPES.join(", ")} are allowed")
    end

    response_types = Array(metadata["response_types"].presence || ["code"])
    if (response_types - SUPPORTED_RESPONSE_TYPES).any?
      return register_error("invalid_client_metadata", "Unsupported response_types; only 'code' is allowed")
    end

    redirect_uris = Array(metadata["redirect_uris"]).map(&:to_s).reject(&:blank?)
    if redirect_uris.empty?
      return register_error("invalid_redirect_uri", "At least one redirect_uri is required")
    end
    invalid = redirect_uris.reject { |uri| valid_redirect_uri?(uri) }
    if invalid.any?
      return register_error("invalid_redirect_uri", "Invalid redirect_uri: #{invalid.first}")
    end

    public_client = (auth_method == "none")
    client_name = metadata["client_name"].to_s.strip.presence || "Dynamically Registered Client"

    application = Application.new(
      name: client_name,
      slug: unique_slug(client_name),
      app_type: "oidc",
      active: true,
      # MCP / OAuth 2.1 expect PKCE; public clients require it automatically.
      require_pkce: true,
      is_public_client: public_client,
      redirect_uris: redirect_uris.to_json,
      metadata: registration_metadata(metadata, auth_method).to_json
    )

    unless application.save
      return register_error("invalid_client_metadata", application.errors.full_messages.join("; "))
    end

    body = {
      client_id: application.client_id,
      client_id_issued_at: application.created_at.to_i,
      redirect_uris: redirect_uris,
      token_endpoint_auth_method: auth_method,
      grant_types: grant_types,
      response_types: response_types,
      client_name: client_name
    }
    body[:scope] = metadata["scope"] if metadata["scope"].present?

    # Return the plaintext secret exactly once, for confidential clients.
    if application.confidential_client?
      body[:client_secret] = application.client_secret
      body[:client_secret_expires_at] = 0 # never expires
    end

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    render json: body, status: :created
  end

  private

  def parse_body
    parsed = JSON.parse(request.raw_post)
    parsed.is_a?(Hash) ? parsed : :invalid
  rescue JSON::ParserError
    :invalid
  end

  def register_error(error, description)
    render json: {error: error, error_description: description}, status: :bad_request
  end

  # RFC 7591 allows https everywhere and http only for loopback (native apps).
  def valid_redirect_uri?(uri)
    parsed = URI.parse(uri)
    return false unless parsed.is_a?(URI::HTTP) # covers HTTP and HTTPS
    return true if parsed.scheme == "https"
    %w[localhost 127.0.0.1 ::1].include?(parsed.host)
  rescue URI::InvalidURIError
    false
  end

  def unique_slug(name)
    base = name.parameterize.presence || "client"
    "#{base.first(40)}-#{SecureRandom.hex(6)}"
  end

  # Preserve the descriptive metadata the client sent for later reference in the
  # admin UI, without letting it drive access.
  def registration_metadata(metadata, auth_method)
    {
      "dynamically_registered" => true,
      "token_endpoint_auth_method" => auth_method,
      "client_uri" => metadata["client_uri"],
      "logo_uri" => metadata["logo_uri"],
      "contacts" => metadata["contacts"],
      "policy_uri" => metadata["policy_uri"],
      "tos_uri" => metadata["tos_uri"],
      "scope" => metadata["scope"]
    }.compact
  end
end
