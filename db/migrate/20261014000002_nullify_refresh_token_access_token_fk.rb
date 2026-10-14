class NullifyRefreshTokenAccessTokenFk < ActiveRecord::Migration[8.1]
  # A refresh token outlives the access token it was issued with by weeks, so
  # when OidcTokenCleanupJob deletes that expired access token, null out the
  # reference rather than blocking the delete on the default RESTRICT (which
  # raised and stopped every sweep after it). Matches the authorization code
  # and device code FKs.
  def up
    change_column_null :oidc_refresh_tokens, :oidc_access_token_id, true
    remove_foreign_key :oidc_refresh_tokens, :oidc_access_tokens
    add_foreign_key :oidc_refresh_tokens, :oidc_access_tokens, on_delete: :nullify
  end

  def down
    remove_foreign_key :oidc_refresh_tokens, :oidc_access_tokens
    add_foreign_key :oidc_refresh_tokens, :oidc_access_tokens
    change_column_null :oidc_refresh_tokens, :oidc_access_token_id, false
  end
end
