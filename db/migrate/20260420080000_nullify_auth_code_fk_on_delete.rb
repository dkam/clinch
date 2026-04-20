class NullifyAuthCodeFkOnDelete < ActiveRecord::Migration[8.1]
  # When an OidcAuthorizationCode is deleted (e.g. by OidcTokenCleanupJob),
  # null out the FK on any descendant tokens instead of blocking the delete
  # on the default RESTRICT. Token rows survive for the audit trail.
  def up
    remove_foreign_key :oidc_access_tokens, :oidc_authorization_codes
    add_foreign_key :oidc_access_tokens, :oidc_authorization_codes, on_delete: :nullify

    remove_foreign_key :oidc_refresh_tokens, :oidc_authorization_codes
    add_foreign_key :oidc_refresh_tokens, :oidc_authorization_codes, on_delete: :nullify
  end

  def down
    remove_foreign_key :oidc_access_tokens, :oidc_authorization_codes
    add_foreign_key :oidc_access_tokens, :oidc_authorization_codes

    remove_foreign_key :oidc_refresh_tokens, :oidc_authorization_codes
    add_foreign_key :oidc_refresh_tokens, :oidc_authorization_codes
  end
end
