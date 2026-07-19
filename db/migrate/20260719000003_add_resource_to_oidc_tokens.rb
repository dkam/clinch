class AddResourceToOidcTokens < ActiveRecord::Migration[8.1]
  # RFC 8707 Resource Indicators: the audience (target resource server) a token
  # is bound to. Threaded from the authorize / device_authorization request
  # through the code and carried across refresh rotation onto the access token,
  # where introspection reports it as `aud`.
  def change
    add_column :oidc_authorization_codes, :resource, :string
    add_column :oidc_device_codes, :resource, :string
    add_column :oidc_access_tokens, :resource, :string
    add_column :oidc_refresh_tokens, :resource, :string
  end
end
