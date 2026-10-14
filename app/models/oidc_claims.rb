# The claim names Clinch sets itself, and the rules custom claims (group, user
# and per-app) follow around them. Shared by the ID token, userinfo and every
# model that stores custom claims, so none of them can drift from the others.
module OidcClaims
  # Custom claims may not use these. The models refuse them when claims are
  # saved, and without_reserved strips them again when a response is built,
  # for rows saved before a name was added here.
  RESERVED = %w[
    iss sub aud exp iat nbf jti nonce azp sid at_hash auth_time acr
    email email_verified preferred_username name updated_at
    groups
  ].freeze

  module_function

  # Custom claims come from JSON columns, so their keys are strings, while the
  # claims Clinch builds are keyed by symbols. A hash holds :acr and "acr" side
  # by side and renders both into the JSON, so names are compared as strings.
  def without_reserved(claims)
    claims.reject { |name, _| RESERVED.include?(name.to_s) }
  end

  # OIDC Core §5.5: when a client sends a claims request, custom claims appear
  # only if it asked for them, and only with the value or values it named.
  def filter_custom(claims, requested)
    requested = requested.to_h.transform_keys(&:to_s)

    claims.select do |name, value|
      name = name.to_s
      next true if RESERVED.include?(name)
      next false unless requested.key?(name)

      spec = requested[name]
      next true unless spec.is_a?(Hash)
      next false if spec["value"].present? && value != spec["value"]
      next false if spec["values"].is_a?(Array) && !spec["values"].include?(value)
      true
    end
  end
end
