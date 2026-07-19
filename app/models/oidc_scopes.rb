# Single source of truth for the OAuth/OIDC scopes this IdP supports. Shared by
# the OIDC controller (discovery + authorize/consent), the device authorization
# flow, and consent handling, so no controller has to reach into another for the
# list.
module OidcScopes
  SUPPORTED = %w[openid profile email groups offline_access].freeze
end
